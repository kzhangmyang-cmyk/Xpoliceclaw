from __future__ import annotations

import datetime as dt
import json
import hashlib
import os
import platform
import re
import subprocess
import threading
import time
import uuid
import csv
from pathlib import Path
from typing import Any

import psutil

from scanner_service import ScanService


UNINSTALL_CONFIRMATION_TEXT = "UNINSTALL CONFIRMED"
UNINSTALL_STEPS = [
    "Identifying target footprint",
    "Terminating active processes",
    "Removing persistence entries",
    "Cleaning config and cache",
    "Removing core files",
    "Verifying leftovers",
    "Finalizing removal record",
]
TASK_ACTIVE_STATUSES = {"pending", "running"}
TASK_TERMINAL_STATUSES = {"success", "failed", "partial"}
HIGH_RISK_THRESHOLD = 70
PROTECTED_SEGMENTS = {
    "documents",
    "desktop",
    "downloads",
    "pictures",
    "music",
    "videos",
    "onedrive",
}
BROWSER_PROFILE_MARKERS = {
    "user data",
    "profiles",
    "default",
    "profile",
    "firefox",
    "chrome",
    "edge",
    "quark",
    "brave",
    "opera",
}
GENERIC_CONTAINER_NAMES = {
    "programs",
    "packages",
    "application support",
    "launchagents",
    "launchdaemons",
    "systemd",
    "user",
}
GENERIC_IDENTITY_NAMES = {
    "microsoft",
    "windows",
    "startup",
    "programs",
    "appdata",
    "local",
    "roaming",
    "users",
    "desktop",
    "documents",
    "downloads",
    "cache",
    "config",
    "temp",
    "tmp",
    "bin",
}
EXECUTABLE_SUFFIXES = {".exe", ".bat", ".cmd", ".ps1", ".sh", ".py", ".pyw", ".js", ".jar", ".com"}
TARGET_CONFIDENCE_THRESHOLD = 0.58
TERMINATE_ONLY_THRESHOLD = 0.66
FULL_UNINSTALL_THRESHOLD = 0.74
HISTORY_LIMIT = 50
HISTORY_VERSION = 1
MIN_STEP_VISIBLE_MS = 110
BLOCKED_REASON_LABELS = {
    "insufficient_evidence": "Insufficient evidence",
    "path_too_broad": "Path too broad",
    "user_data_overlap": "User data overlap",
    "binary_not_safe_to_remove": "Binary not safe to remove",
    "process_only_detection": "Process-only detection",
}


class UninstallService:
    def __init__(self, scan_service: ScanService):
        self.scan_service = scan_service
        self.data_root = self.scan_service.output_root.parent / "data"
        self.data_root.mkdir(parents=True, exist_ok=True)
        self.history_path = self.data_root / "uninstall_history.json"
        self._tasks: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._run_lock = threading.Lock()
        self._persistence_discovery_cache: dict[str, Any] = {}
        self._protected_roots = {
            Path(__file__).resolve().parent,
            Path.cwd().resolve(),
            Path.home().resolve(),
        }
        for value in (
            os.getenv("WINDIR"),
            os.getenv("ProgramFiles"),
            os.getenv("ProgramFiles(x86)"),
            os.getenv("ProgramData"),
        ):
            if value:
                self._protected_roots.add(Path(value).resolve())
        self._load_history()

    def list_targets(self, job_id: str | None = None) -> list[dict[str, Any]]:
        latest = self._get_source_job(job_id)
        if not latest or not latest.get("report"):
            return []

        self._reset_persistence_discovery_cache()
        inferred_targets = self._demo_targets_from_report(latest) or self._merge_targets_by_id(self._infer_targets(latest))
        targets = [self._reassess_target_support(target) for target in inferred_targets]
        history = self._history_index()
        for target in targets:
            previous = self._lookup_history_entry(target, history)
            if not previous:
                target["remediation_state"] = "none"
                target["resolved"] = False
                continue
            target["remediation_state"] = previous["status"]
            target["resolved"] = previous["status"] == "success"
            target["last_uninstall_id"] = previous["id"]
            target["last_uninstall_at"] = previous.get("finished_at") or previous.get("updated_at")
        targets.sort(
            key=lambda item: (
                0 if item["uninstall_supported"] and not item.get("resolved") else 1,
                0 if item.get("support_level") == "full" else 1 if item.get("support_level") == "cleanup" else 2,
                -item["risk_score"],
                -float(item.get("confidence") or 0),
                item["display_name"].lower(),
            )
        )
        return targets

    def _reset_persistence_discovery_cache(self) -> None:
        self._persistence_discovery_cache = {}

    def _demo_targets_from_report(self, job: dict[str, Any]) -> list[dict[str, Any]]:
        report = job.get("report") or {}
        if not report.get("demo_mode"):
            return []
        items = report.get("demo_targets")
        if not isinstance(items, list):
            return []

        targets: list[dict[str, Any]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            risk_score = int(item.get("risk_score") or 0)
            display_name = self._display_name(str(item.get("display_name") or item.get("name") or "Demo Target"))
            executable_paths = self._sort_paths(item.get("executable_paths", []))
            config_paths = self._sort_paths(item.get("config_paths", []))
            cache_paths = self._sort_paths(item.get("cache_paths", []))
            startup_entries = [dict(entry) for entry in item.get("startup_entries", []) if isinstance(entry, dict)]
            primary_executable = item.get("primary_executable") or (executable_paths[0] if executable_paths else None)
            primary_workdir = item.get("primary_workdir")
            if not primary_workdir and primary_executable:
                primary_workdir = str(Path(primary_executable).parent)
            identity_key = item.get("identity_key") or self._build_target_identity(
                display_name=display_name,
                primary_executable=primary_executable,
                primary_workdir=primary_workdir,
            )
            targets.append(
                {
                    "id": self._stable_target_id({"identity_key": identity_key}),
                    "identity_key": identity_key,
                    "name": item.get("name") or display_name,
                    "display_name": display_name,
                    "type": item.get("type") or "local-tool",
                    "vendor": item.get("vendor") or "Demo Fixture",
                    "risk_level": item.get("risk_level") or self._risk_level(risk_score),
                    "risk_score": risk_score,
                    "matched_findings_count": len(item.get("matched_check_ids", [])),
                    "matched_check_ids": sorted(set(item.get("matched_check_ids", []))),
                    "pids": sorted({int(pid) for pid in item.get("pids", [])}),
                    "executable_paths": executable_paths,
                    "config_paths": config_paths,
                    "cache_paths": cache_paths,
                    "startup_entries": startup_entries,
                    "uninstall_supported": False,
                    "unsupported_reason": item.get("unsupported_reason"),
                    "planned_actions": list(item.get("planned_actions", [])),
                    "source_scan_id": job.get("scan_id"),
                    "source_job_id": job.get("id"),
                    "evidence_count": int(item.get("evidence_count") or len(item.get("matched_check_ids", []))),
                    "notes": list(item.get("notes", [])),
                    "path_warnings": list(item.get("path_warnings", [])),
                    "primary_executable": primary_executable,
                    "primary_workdir": primary_workdir,
                    "confidence": float(item.get("confidence") or 0),
                    "evidence_summary": item.get("evidence_summary") or "",
                    "support_level": item.get("support_level") or "blocked",
                    "remove_binary_allowed": bool(item.get("remove_binary_allowed")),
                    "remove_binary_reason": item.get("remove_binary_reason"),
                    "blocked_reason_code": item.get("blocked_reason_code"),
                    "blocked_reason_label": item.get("blocked_reason_label"),
                    "target_summary": item.get("target_summary") or "",
                    "rationale": item.get("rationale") or "",
                    "demo_mode": True,
                }
            )
        return targets

    def _get_source_job(self, job_id: str | None) -> dict[str, Any] | None:
        requested = str(job_id or "").strip()
        if requested:
            selected = self.scan_service.get_job(
                requested,
                include_report=True,
                include_context=True,
            )
            if selected and selected.get("status") == "completed" and selected.get("report"):
                return selected
        return self.scan_service.get_latest_completed_job(
            include_report=True,
            include_context=True,
        )

    def _merge_targets_by_id(self, targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
        merged: dict[str, dict[str, Any]] = {}
        for target in targets:
            merge_key = target.get("identity_key") or target["id"]
            existing = merged.get(merge_key)
            if not existing:
                for candidate_key, candidate in merged.items():
                    if self._should_merge_targets(candidate, target):
                        existing = candidate
                        merge_key = candidate_key
                        break
            if not existing:
                merged[merge_key] = dict(target)
                continue

            existing["risk_score"] = max(existing["risk_score"], target["risk_score"])
            existing["confidence"] = max(
                float(existing.get("confidence") or 0),
                float(target.get("confidence") or 0),
            )
            for key in (
                "matched_check_ids",
                "pids",
                "executable_paths",
                "config_paths",
                "cache_paths",
                "planned_actions",
                "notes",
                "path_warnings",
            ):
                existing[key] = sorted(set(existing.get(key, [])) | set(target.get(key, [])))
            startup_map = {
                f"{item.get('kind')}::{item.get('label')}::{item.get('path', item.get('registry_key', ''))}": item
                for item in existing.get("startup_entries", [])
            }
            for item in target.get("startup_entries", []):
                startup_map.setdefault(
                    f"{item.get('kind')}::{item.get('label')}::{item.get('path', item.get('registry_key', ''))}",
                    item,
                )
            existing["startup_entries"] = list(startup_map.values())

            existing["evidence_count"] = max(
                int(existing.get("evidence_count") or 0),
                int(target.get("evidence_count") or 0),
            )
            existing["display_name"] = self._pick_preferred_text(
                existing.get("display_name"),
                target.get("display_name"),
            )
            existing["name"] = self._pick_preferred_text(existing.get("name"), target.get("name"))
            existing["vendor"] = self._pick_vendor(existing.get("vendor"), target.get("vendor"))
            existing["primary_executable"] = self._pick_preferred_path(
                existing.get("primary_executable"),
                target.get("primary_executable"),
            )
            existing["primary_workdir"] = self._pick_preferred_path(
                existing.get("primary_workdir"),
                target.get("primary_workdir"),
            )
            existing["source_scan_id"] = existing.get("source_scan_id") or target.get("source_scan_id")
            existing["source_job_id"] = existing.get("source_job_id") or target.get("source_job_id")
            existing["evidence_summary"] = self._pick_preferred_text(
                existing.get("evidence_summary"),
                target.get("evidence_summary"),
            )
            existing["identity_key"] = existing.get("identity_key") or target.get("identity_key")

        for target in merged.values():
            target["matched_check_ids"] = sorted(set(target.get("matched_check_ids", [])))
            target["matched_findings_count"] = len(target["matched_check_ids"])
            target["pids"] = sorted({int(pid) for pid in target.get("pids", [])})
            target["executable_paths"] = self._sort_paths(target.get("executable_paths", []))
            target["config_paths"] = self._sort_paths(target.get("config_paths", []))
            target["cache_paths"] = self._sort_paths(target.get("cache_paths", []))
            target["notes"] = list(dict.fromkeys(target.get("notes", [])))[:8]
            target["path_warnings"] = list(dict.fromkeys(target.get("path_warnings", [])))[:8]
            target["startup_entries"] = list(target.get("startup_entries", []))
        return list(merged.values())

    def _should_merge_targets(self, left: dict[str, Any], right: dict[str, Any]) -> bool:
        if str(left.get("source_scan_id") or "") != str(right.get("source_scan_id") or ""):
            return False
        left_name = self._normalize_name(str(left.get("display_name") or left.get("name") or ""))
        right_name = self._normalize_name(str(right.get("display_name") or right.get("name") or ""))
        if not left_name or left_name != right_name:
            return False
        left_checks = set(left.get("matched_check_ids", []))
        right_checks = set(right.get("matched_check_ids", []))
        if not left_checks.intersection(right_checks):
            return False
        left_startup_only = bool(left.get("startup_entries")) and not (left.get("config_paths") or left.get("cache_paths"))
        right_startup_only = bool(right.get("startup_entries")) and not (right.get("config_paths") or right.get("cache_paths"))
        if not (left_startup_only or right_startup_only):
            return False
        return True

    def _reassess_target_support(self, target: dict[str, Any]) -> dict[str, Any]:
        target = dict(target)
        demo_mode = bool(target.get("demo_mode"))
        requested_support_level = target.get("support_level") if demo_mode else None
        requested_confidence = float(target.get("confidence") or 0) if demo_mode else 0.0
        requested_remove_binary = bool(target.get("remove_binary_allowed")) if demo_mode else False
        target["display_name"] = self._pick_target_display_name(target)
        target["name"] = target.get("name") or target["display_name"]
        target["primary_executable"] = self._pick_primary_executable(target)
        target["primary_workdir"] = self._pick_primary_workdir(target)
        target["confidence"] = requested_confidence if requested_confidence else self._calculate_target_confidence(target)
        target["path_warnings"] = list(dict.fromkeys(target.get("path_warnings", [])))
        target["remove_binary_allowed"] = requested_remove_binary if demo_mode else self._can_remove_binary(target)
        target["remove_binary_reason"] = None
        target["blocked_reason_code"] = None
        target["blocked_reason_label"] = None
        target["target_summary"] = ""
        target["rationale"] = ""

        if target.get("executable_paths") and not target["remove_binary_allowed"]:
            target["remove_binary_reason"] = target.get("remove_binary_reason") or self._binary_block_reason(target)

        name_agent_like = self._looks_like_agent_name(target["display_name"]) or any(
            self._looks_like_agent_name(Path(path).stem)
            for path in target.get("executable_paths", [])
        )
        has_cleanup_paths = bool(
            target.get("config_paths")
            or target.get("cache_paths")
            or target.get("startup_entries")
        )
        has_pids = bool(target.get("pids"))
        has_binary = bool(target.get("executable_paths"))

        support_level = "blocked"
        unsupported_reason = target.get("unsupported_reason")
        if demo_mode and requested_support_level in {"full", "cleanup", "terminate_only", "blocked"}:
            support_level = requested_support_level
            if support_level != "blocked":
                unsupported_reason = None
        else:
            unsupported_reason = None
            if float(target["confidence"]) < TARGET_CONFIDENCE_THRESHOLD:
                unsupported_reason = "Target confidence is too low to allow an automated removal run."
            elif not name_agent_like and not has_cleanup_paths:
                unsupported_reason = "Current MVP only auto-removes targets whose script, app, or process identity is clearly agent-style."
            elif has_cleanup_paths or target["remove_binary_allowed"]:
                support_level = "full" if target["remove_binary_allowed"] else "cleanup"
            elif has_pids and float(target["confidence"]) >= TERMINATE_ONLY_THRESHOLD:
                support_level = "terminate_only"
            elif has_binary:
                unsupported_reason = target["remove_binary_reason"] or "Binary path was found but was not safe enough to remove automatically."
            else:
                unsupported_reason = "Missing a removable footprint beyond runtime process indicators."

        if support_level == "cleanup" and not target["remove_binary_allowed"] and target.get("remove_binary_reason"):
            target["notes"] = list(dict.fromkeys(target.get("notes", []) + [target["remove_binary_reason"]]))

        blocked_code, blocked_label, blocked_detail = self._classify_blocked_reason(target, unsupported_reason)
        target["support_level"] = support_level
        target["uninstall_supported"] = support_level in {"full", "cleanup", "terminate_only"}
        target["unsupported_reason"] = unsupported_reason
        target["blocked_reason_code"] = blocked_code if support_level == "blocked" else None
        target["blocked_reason_label"] = blocked_label if support_level == "blocked" else None
        if support_level == "blocked" and blocked_detail and blocked_detail != unsupported_reason:
            target["notes"] = list(dict.fromkeys(target.get("notes", []) + [blocked_detail]))
        target["planned_actions"] = self._build_target_actions(target)
        target["evidence_summary"] = self._build_target_evidence_summary(target)
        target["target_summary"] = self._build_target_summary(target)
        target["rationale"] = self._build_target_rationale(target)
        target["id"] = self._stable_target_id(target)
        return target

    def create_uninstall_task(self, request_options: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        active = self._get_active_task()
        if active:
            return self._snapshot_task(active), False

        if request_options.get("confirmation_text") != UNINSTALL_CONFIRMATION_TEXT:
            raise ValueError("Confirmation text must be exactly 'UNINSTALL CONFIRMED'.")

        target_id = str(request_options.get("target_id") or "").strip()
        if not target_id:
            raise ValueError("target_id is required.")

        source_job = self._get_source_job(request_options.get("job_id"))
        targets = {item["id"]: item for item in self.list_targets(request_options.get("job_id"))}
        target = targets.get(target_id)
        if not target:
            raise ValueError("Unknown uninstall target.")
        if not target.get("uninstall_supported"):
            raise ValueError(target.get("unsupported_reason") or "Target is not safe to uninstall.")

        now = self._now()
        task_id = uuid.uuid4().hex[:10]
        task = {
            "id": task_id,
            "target_id": target["id"],
            "target_name": target["name"],
            "target_type": target["type"],
            "source_job_id": source_job.get("id") if source_job else target.get("source_job_id"),
            "source_scan_id": source_job.get("scan_id") if source_job else target.get("source_scan_id"),
            "status": "pending",
            "created_at": now,
            "updated_at": now,
            "started_at": None,
            "finished_at": None,
            "duration_ms": None,
            "progress": 0,
            "current_step": None,
            "steps": self._build_steps(),
            "step_history": [],
            "logs": [],
            "removed_items": [],
            "preserved_items": [],
            "leftover_items": [],
            "error": None,
            "request_options": {
                "job_id": source_job.get("id") if source_job else request_options.get("job_id"),
                "mode": request_options.get("mode") or "standard",
                "remove_startup": bool(request_options.get("remove_startup")),
                "remove_cache": bool(request_options.get("remove_cache")),
                "remove_config": bool(request_options.get("remove_config")),
                "remove_binary": bool(request_options.get("remove_binary")),
                "confirmation_text": request_options.get("confirmation_text"),
            },
            "result": None,
            "target": target,
            "_pending_terminal_state": None,
            "_started_monotonic": None,
        }

        with self._lock:
            self._tasks[task_id] = task

        worker = threading.Thread(
            target=self._run_uninstall_task,
            args=(task_id,),
            daemon=True,
        )
        worker.start()
        return self._snapshot_task(task), True

    def get_uninstall_task(self, task_id: str) -> dict[str, Any] | None:
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return None
            return self._snapshot_task(task)

    def get_uninstall_result(self, task_id: str) -> dict[str, Any] | None:
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return None
            return {
                "id": task["id"],
                "target_id": task["target_id"],
                "target_name": task["target_name"],
                "source_job_id": task.get("source_job_id"),
                "source_scan_id": task.get("source_scan_id"),
                "status": task["status"],
                "finished_at": task["finished_at"],
                "duration_ms": task.get("duration_ms"),
                "steps": [dict(step) for step in task["steps"]],
                "step_history": list(task.get("step_history", [])),
                "removed_items": list(task["removed_items"]),
                "preserved_items": list(task["preserved_items"]),
                "leftover_items": list(task["leftover_items"]),
                "logs": list(task["logs"]),
                "error": task["error"],
                "target": dict(task.get("target") or {}),
                "result": dict(task["result"]) if isinstance(task["result"], dict) else task["result"],
            }

    def list_uninstall_history(self) -> list[dict[str, Any]]:
        with self._lock:
            tasks = list(self._tasks.values())
        tasks.sort(key=lambda item: item["created_at"], reverse=True)
        return [self._snapshot_task(task) for task in tasks]

    def import_history_task(
        self,
        *,
        target: dict[str, Any],
        status: str,
        removed_items: list[dict[str, Any]] | None = None,
        preserved_items: list[dict[str, Any]] | None = None,
        leftover_items: list[dict[str, Any]] | None = None,
        logs: list[dict[str, Any]] | None = None,
        request_options: dict[str, Any] | None = None,
        duration_ms: int = 920,
        error: str | None = None,
        created_at: str | None = None,
        started_at: str | None = None,
        finished_at: str | None = None,
    ) -> dict[str, Any]:
        if status not in TASK_TERMINAL_STATUSES:
            raise ValueError("Seeded uninstall history must use a terminal status.")

        now = self._now()
        created_at = self._coerce_iso_timestamp(created_at, fallback=now)
        started_at = self._coerce_iso_timestamp(started_at, fallback=created_at)
        finished_at = self._coerce_iso_timestamp(finished_at, fallback=now)
        duration_ms = max(int(duration_ms or 0), 120)
        task_id = uuid.uuid4().hex[:10]
        steps, step_history = self._seed_step_records(
            status=status,
            started_at=started_at,
            duration_ms=duration_ms,
            error=error,
        )
        task = {
            "id": task_id,
            "target_id": target["id"],
            "target_name": target.get("display_name") or target.get("name") or "Imported Target",
            "target_type": target.get("type") or "local-tool",
            "source_job_id": target.get("source_job_id"),
            "source_scan_id": target.get("source_scan_id"),
            "status": status,
            "created_at": created_at,
            "updated_at": finished_at,
            "started_at": started_at,
            "finished_at": finished_at,
            "duration_ms": duration_ms,
            "progress": 100,
            "current_step": UNINSTALL_STEPS[-1],
            "steps": steps,
            "step_history": step_history,
            "logs": [dict(entry) for entry in (logs or [])][-80:],
            "removed_items": [dict(entry) for entry in (removed_items or [])],
            "preserved_items": [dict(entry) for entry in (preserved_items or [])],
            "leftover_items": [dict(entry) for entry in (leftover_items or [])],
            "error": error,
            "request_options": {
                "mode": "standard",
                "remove_startup": bool(target.get("startup_entries")),
                "remove_cache": bool(target.get("cache_paths")),
                "remove_config": bool(target.get("config_paths")),
                "remove_binary": bool(target.get("remove_binary_allowed")),
                **dict(request_options or {}),
            },
            "result": None,
            "target": dict(target),
            "_pending_terminal_state": None,
            "_started_monotonic": None,
        }

        with self._lock:
            self._tasks[task_id] = task
        task["result"] = self._build_task_result(task_id, task["target"], status=status)
        self._persist_history()
        return self.get_uninstall_task(task_id) or {}

    def _load_history(self) -> None:
        if not self.history_path.exists():
            return
        try:
            payload = json.loads(self.history_path.read_text(encoding="utf-8"))
        except Exception:
            return
        items = payload.get("items") if isinstance(payload, dict) else None
        if not isinstance(items, list):
            return
        restored: dict[str, dict[str, Any]] = {}
        for item in items[:HISTORY_LIMIT]:
            task = self._restore_task(item)
            if task:
                restored[task["id"]] = task
        with self._lock:
            self._tasks.update(restored)

    def _persist_history(self) -> None:
        with self._lock:
            items = [
                self._serialize_task_for_history(task)
                for task in self._tasks.values()
                if task["status"] in TASK_TERMINAL_STATUSES
            ]
        items.sort(key=lambda item: item["created_at"], reverse=True)
        self._write_json_atomic(
            self.history_path,
            {
                "version": HISTORY_VERSION,
                "saved_at": self._now(),
                "items": items[:HISTORY_LIMIT],
            },
        )

    def _serialize_task_for_history(self, task: dict[str, Any]) -> dict[str, Any]:
        request_options = dict(task.get("request_options") or {})
        request_options.pop("confirmation_text", None)
        return {
            "id": task["id"],
            "target_id": task.get("target_id"),
            "target_name": task.get("target_name"),
            "target_type": task.get("target_type"),
            "source_job_id": task.get("source_job_id"),
            "source_scan_id": task.get("source_scan_id"),
            "status": task.get("status"),
            "created_at": task.get("created_at"),
            "updated_at": task.get("updated_at"),
            "started_at": task.get("started_at"),
            "finished_at": task.get("finished_at"),
            "duration_ms": task.get("duration_ms"),
            "progress": task.get("progress", 0),
            "current_step": task.get("current_step"),
            "steps": [dict(step) for step in task.get("steps", [])],
            "step_history": [dict(item) for item in task.get("step_history", [])],
            "logs": [dict(item) for item in task.get("logs", [])][-80:],
            "removed_items": [dict(item) for item in task.get("removed_items", [])],
            "preserved_items": [dict(item) for item in task.get("preserved_items", [])],
            "leftover_items": [dict(item) for item in task.get("leftover_items", [])],
            "error": task.get("error"),
            "request_options": request_options,
            "result": dict(task.get("result") or {}) if isinstance(task.get("result"), dict) else task.get("result"),
            "target": dict(task.get("target") or {}),
        }

    def _restore_task(self, item: dict[str, Any]) -> dict[str, Any] | None:
        task_id = str(item.get("id") or "").strip()
        if not task_id:
            return None
        return {
            "id": task_id,
            "target_id": item.get("target_id"),
            "target_name": item.get("target_name") or "Unknown Target",
            "target_type": item.get("target_type") or "local-tool",
            "source_job_id": item.get("source_job_id"),
            "source_scan_id": item.get("source_scan_id"),
            "status": item.get("status") or "failed",
            "created_at": item.get("created_at") or self._now(),
            "updated_at": item.get("updated_at") or item.get("created_at") or self._now(),
            "started_at": item.get("started_at"),
            "finished_at": item.get("finished_at"),
            "duration_ms": item.get("duration_ms"),
            "progress": int(item.get("progress") or 0),
            "current_step": item.get("current_step"),
            "steps": [dict(step) for step in item.get("steps", [])] or self._build_steps(),
            "step_history": [dict(step) for step in item.get("step_history", [])],
            "logs": [dict(entry) for entry in item.get("logs", [])][-80:],
            "removed_items": [dict(entry) for entry in item.get("removed_items", [])],
            "preserved_items": [dict(entry) for entry in item.get("preserved_items", [])],
            "leftover_items": [dict(entry) for entry in item.get("leftover_items", [])],
            "error": item.get("error"),
            "request_options": dict(item.get("request_options") or {}),
            "result": dict(item.get("result") or {}) if isinstance(item.get("result"), dict) else item.get("result"),
            "target": dict(item.get("target") or {}),
            "_pending_terminal_state": None,
            "_started_monotonic": None,
        }

    def _write_json_atomic(self, path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = path.with_suffix(f"{path.suffix}.tmp")
        temp_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        temp_path.replace(path)

    def _coerce_iso_timestamp(self, value: str | None, *, fallback: str) -> str:
        text = str(value or "").strip()
        if not text:
            return fallback
        normalized = text.replace(" ", "T")
        try:
            return dt.datetime.fromisoformat(normalized).isoformat(timespec="seconds")
        except ValueError:
            return fallback

    def _seed_step_records(
        self,
        *,
        status: str,
        started_at: str,
        duration_ms: int,
        error: str | None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        steps = self._build_steps()
        started_dt = dt.datetime.fromisoformat(started_at.replace(" ", "T"))
        per_step_ms = max(duration_ms // max(len(UNINSTALL_STEPS), 1), 60)
        history: list[dict[str, Any]] = []
        for index, step in enumerate(steps):
            step_started = started_dt + dt.timedelta(milliseconds=index * per_step_ms)
            step_finished = step_started + dt.timedelta(milliseconds=per_step_ms)
            step_status = "done"
            step_error = None
            if status == "failed" and index == len(steps) - 1:
                step_status = "failed"
                step_error = error or "Seeded demo failure."
            step["status"] = step_status
            step["started_at"] = step_started.isoformat(timespec="seconds")
            step["finished_at"] = step_finished.isoformat(timespec="seconds")
            step["duration_ms"] = per_step_ms
            history.append(
                {
                    "index": step["index"],
                    "label": step["label"],
                    "status": step_status,
                    "started_at": step["started_at"],
                    "finished_at": step["finished_at"],
                    "duration_ms": per_step_ms,
                    "error": step_error,
                }
            )
        return steps, history

    def _get_active_task(self) -> dict[str, Any] | None:
        with self._lock:
            active = [
                task for task in self._tasks.values()
                if task["status"] in TASK_ACTIVE_STATUSES
            ]
            if not active:
                return None
            active.sort(key=lambda item: item["created_at"], reverse=True)
            return active[0]

    def _history_index(self) -> dict[str, dict[str, Any]]:
        history: dict[str, dict[str, Any]] = {}
        for task in self.list_uninstall_history():
            for key in self._history_keys_for_task(task):
                history.setdefault(key, task)
        return history

    def _lookup_history_entry(
        self,
        target: dict[str, Any],
        history: dict[str, dict[str, Any]],
    ) -> dict[str, Any] | None:
        for key in self._history_keys_for_target(target):
            previous = history.get(key)
            if previous and self._same_source(target, previous):
                return previous
        return None

    def _same_source(self, target: dict[str, Any], previous: dict[str, Any]) -> bool:
        target_job = str(target.get("source_job_id") or "").strip()
        previous_job = str(previous.get("source_job_id") or "").strip()
        if target_job and previous_job and target_job != previous_job:
            return False
        target_scan = str(target.get("source_scan_id") or "").strip()
        previous_scan = str(previous.get("source_scan_id") or "").strip()
        if target_scan and previous_scan and target_scan != previous_scan:
            return False
        return True

    def _history_keys_for_task(self, task: dict[str, Any]) -> list[str]:
        target = task.get("target") or {}
        keys = [task.get("target_id"), task.get("target_name"), target.get("display_name")]
        keys.extend(
            Path(path).stem
            for path in target.get("executable_paths", [])
            if path
        )
        keys.extend(
            Path(path).name
            for path in target.get("config_paths", [])[:1]
            if path
        )
        return self._normalize_history_keys(keys)

    def _history_keys_for_target(self, target: dict[str, Any]) -> list[str]:
        keys = [target.get("id"), target.get("name"), target.get("display_name"), target.get("identity_key")]
        keys.extend(
            Path(path).stem
            for path in target.get("executable_paths", [])
            if path
        )
        if target.get("primary_workdir"):
            keys.append(Path(target["primary_workdir"]).name)
        return self._normalize_history_keys(keys)

    def _normalize_history_keys(self, values: list[str | None]) -> list[str]:
        normalized = []
        for value in values:
            if not value:
                continue
            text = str(value).strip()
            if not text:
                continue
            normalized.append(text)
            normalized.append(self._normalize_name(text))
        return list(dict.fromkeys(item for item in normalized if item))

    def _infer_targets(self, job: dict[str, Any]) -> list[dict[str, Any]]:
        report = job.get("report") or {}
        context = job.get("context") or {}
        processes = context.get("collector", {}).get("processes", [])
        connections = context.get("collector", {}).get("connections", [])
        process_map = {
            int(proc.get("pid")): proc
            for proc in processes
            if proc.get("pid") is not None
        }

        candidates: dict[str, dict[str, Any]] = {}
        for check in report.get("checks", []):
            if not check.get("detected"):
                continue
            if int(check.get("risk_score") or 0) < HIGH_RISK_THRESHOLD:
                continue

            keys_for_check: set[str] = set()
            for evidence in check.get("evidence") or []:
                for candidate_key in self._candidate_keys_for_evidence(evidence, process_map):
                    candidate = candidates.setdefault(
                        candidate_key,
                        self._new_candidate(candidate_key, report.get("scan_id")),
                    )
                    keys_for_check.add(candidate_key)
                    self._apply_evidence(candidate, evidence, check, process_map, connections)

            if not keys_for_check and check.get("evidence"):
                fallback_key = f"check:{check['id']}"
                candidate = candidates.setdefault(
                    fallback_key,
                    self._new_candidate(fallback_key, report.get("scan_id")),
                )
                self._apply_check_only(candidate, check)

        targets = []
        for candidate in candidates.values():
            target = self._finalize_candidate(candidate)
            if target:
                target["source_job_id"] = job.get("id")
                targets.append(target)
        return targets

    def _candidate_keys_for_evidence(
        self,
        evidence: dict[str, Any],
        process_map: dict[int, dict[str, Any]],
    ) -> list[str]:
        pid = evidence.get("pid")
        if pid is not None:
            process_info = process_map.get(int(pid)) or {}
            process_path = self._infer_process_path(process_info)
            if process_path and self._is_binary_path(process_path):
                return [f"exec:{process_path}"]
            if process_path and process_path.parent:
                return [f"workdir:{process_path.parent}"]
            anchor = self._candidate_anchor_path(process_path) if process_path else None
            if anchor:
                return [f"path:{anchor}"]
            name = process_info.get("name") or evidence.get("name")
            if name:
                return [f"proc:{self._normalize_name(name)}"]

        binary_paths = [
            path for path in self._extract_paths(evidence)
            if self._is_binary_path(path)
        ]
        if binary_paths:
            return [f"exec:{binary_paths[0]}"]

        anchored_paths = [
            self._candidate_anchor_path(path)
            for path in self._extract_paths(evidence)
        ]
        anchored_paths = [path for path in anchored_paths if path]
        if anchored_paths:
            return [f"path:{anchored_paths[0]}"]

        explicit_paths = self._extract_paths(evidence)
        if explicit_paths:
            workdir = explicit_paths[0].parent if explicit_paths[0].parent else None
            if workdir:
                return [f"workdir:{workdir}"]

        pid = evidence.get("pid")
        if pid is not None:
            return [f"pid:{int(pid)}"]
        if evidence.get("name"):
            return [f"proc:{self._normalize_name(evidence['name'])}"]
        return []

    def _new_candidate(self, key: str, scan_id: str | None) -> dict[str, Any]:
        return {
            "key": key,
            "scan_id": scan_id,
            "names": set(),
            "vendors": set(),
            "matched_check_ids": set(),
            "matched_labels": set(),
            "risk_scores": [],
            "pids": set(),
            "evidence_count": 0,
            "anchors": set(),
            "executable_paths": set(),
            "config_paths": set(),
            "cache_paths": set(),
            "startup_entries": [],
            "notes": [],
            "unsupported_reasons": [],
            "types": set(),
            "browser_like": False,
            "protected_hit": False,
            "process_names": set(),
            "workdirs": set(),
            "commands": set(),
        }

    def _apply_check_only(self, candidate: dict[str, Any], check: dict[str, Any]) -> None:
        candidate["matched_check_ids"].add(check["id"])
        candidate["matched_labels"].add(check["label"])
        candidate["risk_scores"].append(int(check.get("risk_score") or 0))
        candidate["evidence_count"] += int(check.get("evidence_count") or 0)
        candidate["notes"].append("Evidence existed but no removable footprint could be derived safely.")

    def _apply_evidence(
        self,
        candidate: dict[str, Any],
        evidence: dict[str, Any],
        check: dict[str, Any],
        process_map: dict[int, dict[str, Any]],
        connections: list[dict[str, Any]],
    ) -> None:
        candidate["matched_check_ids"].add(check["id"])
        candidate["matched_labels"].add(check["label"])
        candidate["risk_scores"].append(int(check.get("risk_score") or 0))
        candidate["evidence_count"] += 1

        for path in self._extract_paths(evidence):
            self._attach_path(candidate, path)

        pid = evidence.get("pid")
        if pid is not None:
            candidate["pids"].add(int(pid))
            process_info = process_map.get(int(pid)) or {}
            process_name = process_info.get("name") or evidence.get("name")
            if process_name:
                candidate["process_names"].add(process_name)
                candidate["names"].add(self._display_name(process_name))
            inferred = self._infer_process_path(process_info)
            if inferred:
                self._attach_path(candidate, inferred, prefer_binary=True)
                candidate["workdirs"].add(str(inferred.parent))
            cmdline = str(process_info.get("cmdline") or "").strip()
            if cmdline:
                candidate["commands"].add(cmdline)
            text = " ".join(
                str(value or "")
                for value in (
                    process_info.get("name"),
                    process_info.get("cmdline"),
                    evidence.get("match"),
                )
            ).lower()
            candidate["types"].add(self._infer_target_type(text, inferred))
            candidate["vendors"].update(self._infer_vendor_values(inferred, process_name))

            related_files = [
                Path(file_path)
                for file_path in process_info.get("open_files") or []
                if isinstance(file_path, str)
            ]
            for file_path in related_files[:10]:
                if not any(self._is_subpath(file_path, base) for base in self._user_scoped_bases()):
                    continue
                self._attach_path(candidate, file_path)

            related_connections = [
                conn for conn in connections
                if int(conn.get("pid") or -1) == int(pid)
            ]
            if related_connections:
                candidate["notes"].append(
                    f"Active outbound context seen on {len(related_connections)} connection(s)."
                )

        if evidence.get("type") in {"network", "traffic", "api_endpoint"}:
            endpoint = evidence.get("endpoint") or evidence.get("endpoints")
            if endpoint:
                candidate["notes"].append(f"Network indicator: {endpoint}")

    def _attach_path(
        self,
        candidate: dict[str, Any],
        raw_path: str | Path,
        *,
        prefer_binary: bool = False,
    ) -> None:
        path = self._coerce_path(raw_path)
        if not path:
            return

        anchor = self._candidate_anchor_path(path)
        if anchor:
            candidate["anchors"].add(str(anchor))

        if self._looks_like_browser_profile(path):
            candidate["browser_like"] = True

        if self._is_protected_path(path):
            candidate["protected_hit"] = True
            candidate["unsupported_reasons"].append(f"Protected or overly broad path: {path}")
            return

        if self._is_binary_path(path) or prefer_binary:
            candidate["executable_paths"].add(str(path))
        elif self._looks_like_cache(path):
            candidate["cache_paths"].add(str(self._best_removal_root(path)))
        else:
            candidate["config_paths"].add(str(self._best_removal_root(path)))

        candidate["names"].update(self._infer_name_values(path))
        candidate["vendors"].update(self._infer_vendor_values(path, None))
        candidate["types"].add(self._infer_target_type(str(path).lower(), path))

    def _finalize_candidate(self, candidate: dict[str, Any]) -> dict[str, Any] | None:
        names = sorted(candidate["names"])
        check_ids = sorted(candidate["matched_check_ids"])
        if not check_ids:
            return None

        risk_score = max(candidate["risk_scores"] or [0])
        anchor_name = None
        if candidate["anchors"]:
            anchor_name = self._display_name(Path(sorted(candidate["anchors"])[0]).name)
        fallback_name = self._display_name(candidate["key"].split(":", 1)[-1])
        target_name = anchor_name or (names[0] if names else fallback_name)
        startup_entries = self._discover_persistence_entries(candidate)
        candidate["startup_entries"] = startup_entries

        config_paths = self._sort_paths(candidate["config_paths"])
        cache_paths = self._sort_paths(candidate["cache_paths"])
        executable_paths = self._sort_paths(candidate["executable_paths"])
        pids = sorted(candidate["pids"])
        target_type = self._pick_target_type(candidate["types"])
        display_name = self._display_name(target_name)
        primary_executable = executable_paths[0] if executable_paths else None
        primary_workdir = self._coerce_path(primary_executable).parent if primary_executable else None
        if not primary_workdir and candidate["workdirs"]:
            primary_workdir = self._coerce_path(sorted(candidate["workdirs"])[0])
        if not primary_workdir and candidate["anchors"]:
            primary_workdir = self._coerce_path(sorted(candidate["anchors"])[0])
        identity_key = self._build_target_identity(
            display_name=display_name,
            primary_executable=primary_executable,
            primary_workdir=primary_workdir,
        )
        confidence = self._candidate_confidence(candidate, executable_paths, config_paths, cache_paths, startup_entries)
        notes = list(dict.fromkeys(candidate["notes"]))[:8]
        path_warnings = list(dict.fromkeys(candidate["unsupported_reasons"]))[:8]

        return {
            "id": identity_key,
            "name": target_name,
            "display_name": display_name,
            "type": target_type,
            "vendor": ", ".join(sorted(candidate["vendors"])[:2]) or "Unknown",
            "risk_level": self._risk_level(risk_score),
            "risk_score": risk_score,
            "matched_findings_count": len(check_ids),
            "matched_check_ids": check_ids,
            "pids": pids,
            "executable_paths": executable_paths,
            "config_paths": config_paths,
            "cache_paths": cache_paths,
            "startup_entries": startup_entries,
            "uninstall_supported": False,
            "unsupported_reason": None,
            "planned_actions": [],
            "source_scan_id": candidate.get("scan_id"),
            "source_job_id": None,
            "evidence_count": candidate["evidence_count"],
            "notes": notes,
            "path_warnings": path_warnings,
            "primary_executable": primary_executable,
            "primary_workdir": str(primary_workdir) if primary_workdir else None,
            "confidence": confidence,
            "evidence_summary": "",
            "identity_key": identity_key,
            "support_level": "blocked",
            "remove_binary_allowed": False,
            "remove_binary_reason": None,
            "blocked_reason_code": None,
            "blocked_reason_label": None,
            "target_summary": "",
            "rationale": "",
        }

    def _stable_target_id(self, target: dict[str, Any]) -> str:
        identity = (
            target.get("identity_key")
            or target.get("primary_executable")
            or target.get("primary_workdir")
            or target.get("display_name")
            or target.get("name")
            or uuid.uuid4().hex[:10]
        )
        slug = re.sub(r"[^a-z0-9]+", "-", str(identity).lower()).strip("-")
        digest = hashlib.sha1(str(identity).encode("utf-8", errors="ignore")).hexdigest()[:8]
        trimmed = slug[-42:] if slug else "target"
        return f"{trimmed}-{digest}"

    def _discover_persistence_entries(self, candidate: dict[str, Any]) -> list[dict[str, Any]]:
        names = sorted(candidate["process_names"] or candidate["names"])
        paths = self._sort_paths(candidate["executable_paths"] | candidate["config_paths"] | candidate["cache_paths"])
        entries: list[dict[str, Any]] = []
        system = platform.system()
        if system == "Windows":
            entries.extend(self._discover_windows_persistence(names, paths))
        elif system == "Darwin":
            entries.extend(self._discover_macos_persistence(names, paths))
        else:
            entries.extend(self._discover_linux_persistence(names, paths))
        return entries

    def _get_cached_persistence(self, key: str, loader):
        if key not in self._persistence_discovery_cache:
            self._persistence_discovery_cache[key] = loader()
        return self._persistence_discovery_cache[key]

    def _load_windows_startup_entries(self) -> list[dict[str, Any]]:
        startup_root = self._windows_startup_root()
        if not startup_root.exists():
            return []
        items = []
        for item in startup_root.iterdir():
            if item.name.lower() == "desktop.ini":
                continue
            items.append(
                {
                    "kind": "startup_file",
                    "label": item.name,
                    "path": str(item),
                    "haystack": f"{item.name} {item}".lower(),
                }
            )
        return items

    def _load_windows_run_entries(self) -> list[dict[str, Any]]:
        run_key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
        try:
            output = subprocess.check_output(
                ["reg", "query", run_key],
                text=True,
                encoding="utf-8",
                errors="ignore",
                timeout=5,
            )
        except Exception:
            output = ""

        entries = []
        for line in output.splitlines():
            parts = re.split(r"\s{2,}", line.strip())
            if len(parts) < 3:
                continue
            entries.append(
                {
                    "kind": "registry_run",
                    "label": parts[0],
                    "registry_key": run_key,
                    "command": parts[-1],
                    "haystack": line.lower(),
                }
            )
        return entries

    def _load_windows_scheduled_entries(self) -> list[dict[str, Any]]:
        try:
            scheduled_csv = subprocess.check_output(
                ["schtasks", "/query", "/fo", "CSV", "/v"],
                text=True,
                encoding="utf-8",
                errors="ignore",
                timeout=8,
            )
        except Exception:
            scheduled_csv = ""

        entries = []
        if not scheduled_csv:
            return entries
        reader = csv.DictReader(scheduled_csv.splitlines())
        for row in reader:
            task_name = (row.get("TaskName") or row.get("Task Name") or "").strip()
            if not task_name or task_name.lower().startswith("\\microsoft\\"):
                continue
            run_as = (row.get("Run As User") or row.get("Run As User Name") or "").lower()
            if any(marker in run_as for marker in ("system", "service", "localservice", "networkservice")):
                continue
            command = (
                row.get("Task To Run")
                or row.get("Actions")
                or row.get("Action")
                or row.get("Task To Run (Executable)")
                or ""
            ).strip()
            entries.append(
                {
                    "kind": "scheduled_task",
                    "label": task_name.lstrip("\\"),
                    "task_name": task_name,
                    "command": command,
                    "haystack": f"{task_name} {command}".lower(),
                }
            )
        return entries

    def _discover_windows_persistence(self, names: list[str], paths: list[str]) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        for item in self._get_cached_persistence("windows_startup", self._load_windows_startup_entries):
            if self._matches_target_identity(item.get("haystack", ""), names, paths):
                entries.append({key: value for key, value in item.items() if key != "haystack"})

        for item in self._get_cached_persistence("windows_run", self._load_windows_run_entries):
            if self._matches_target_identity(item.get("haystack", ""), names, paths):
                entries.append({key: value for key, value in item.items() if key != "haystack"})

        for item in self._get_cached_persistence("windows_schtasks", self._load_windows_scheduled_entries):
            if self._matches_target_identity(item.get("haystack", ""), names, paths):
                entries.append({key: value for key, value in item.items() if key != "haystack"})
        return entries

    def _discover_macos_persistence(self, names: list[str], paths: list[str]) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        launch_agents = Path.home() / "Library" / "LaunchAgents"
        if launch_agents.exists():
            for item in launch_agents.glob("*.plist"):
                haystack = f"{item.name} {item.read_text(encoding='utf-8', errors='ignore')}".lower()
                if self._matches_target_identity(haystack, names, paths):
                    entries.append({
                        "kind": "launch_agent",
                        "label": item.name,
                        "path": str(item),
                    })
        return entries

    def _discover_linux_persistence(self, names: list[str], paths: list[str]) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        systemd_user = Path.home() / ".config" / "systemd" / "user"
        if systemd_user.exists():
            for item in systemd_user.glob("*.service"):
                haystack = f"{item.name} {item.read_text(encoding='utf-8', errors='ignore')}".lower()
                if self._matches_target_identity(haystack, names, paths):
                    entries.append({
                        "kind": "systemd_user_service",
                        "label": item.name,
                        "path": str(item),
                    })
        autostart_root = Path.home() / ".config" / "autostart"
        if autostart_root.exists():
            for item in autostart_root.glob("*.desktop"):
                haystack = f"{item.name} {item.read_text(encoding='utf-8', errors='ignore')}".lower()
                if self._matches_target_identity(haystack, names, paths):
                    entries.append({
                        "kind": "autostart_desktop",
                        "label": item.name,
                        "path": str(item),
                    })
        return entries

    def _run_uninstall_task(self, task_id: str) -> None:
        try:
            with self._run_lock:
                start_clock = time.perf_counter()
                self._set_task_state(
                    task_id,
                    status="running",
                    started_at=self._now(),
                    _started_monotonic=start_clock,
                )
                target = self._require_task(task_id)["target"]
                options = self._require_task(task_id)["request_options"]
                plan = self._build_execution_plan(target, options)

                self._run_step(task_id, 0, lambda: self._step_identify(task_id, target, plan))
                self._run_step(task_id, 1, lambda: self._step_terminate(task_id, target, plan))
                self._run_step(task_id, 2, lambda: self._step_persistence(task_id, target, plan))
                self._run_step(task_id, 3, lambda: self._step_clean(task_id, target, plan))
                self._run_step(task_id, 4, lambda: self._step_remove_binaries(task_id, target, plan))
                self._run_step(task_id, 5, lambda: self._step_verify(task_id, target, plan))
                self._run_step(task_id, 6, lambda: self._step_finalize(task_id, target, plan))
        except Exception as exc:
            self._append_log(task_id, f"Task failed unexpectedly: {exc}", level="error")
            result = self._build_task_result(task_id, self._require_task(task_id)["target"], status="failed")
            self._set_task_state(
                task_id,
                status="failed",
                error=str(exc),
                finished_at=self._now(),
                duration_ms=self._task_duration_ms(task_id),
                result=result,
                _started_monotonic=None,
            )
            self._persist_history()

    def _step_identify(self, task_id: str, target: dict[str, Any], plan: dict[str, Any]) -> None:
        self._append_log(task_id, f"Preparing uninstall plan for {target['name']}.")
        for item in plan["rejected_paths"]:
            self._record_preserved(task_id, item["type"], item["value"], item["detail"])
            self._append_log(task_id, f"Rejected {item['type']} path {item['value']}: {item['detail']}", level="warning")
        if not plan["all_paths"] and not plan["startup_entries"] and not plan["pids"]:
            raise RuntimeError("No actionable footprint remained after safety validation.")
        self._append_log(
            task_id,
            f"Plan includes {len(plan['pids'])} process(es), {len(plan['startup_entries'])} persistence item(s), and {len(plan['all_paths'])} file path(s).",
        )

    def _step_terminate(self, task_id: str, target: dict[str, Any], plan: dict[str, Any]) -> None:
        if not plan["pids"]:
            self._append_log(task_id, "No active processes were linked to the target.")
            return

        for pid in plan["pids"]:
            try:
                process = psutil.Process(pid)
            except psutil.Error:
                self._append_log(task_id, f"Process {pid} was already gone.")
                continue

            executable = ""
            cmdline = ""
            try:
                executable = process.exe()
            except psutil.Error:
                executable = ""
            try:
                cmdline = " ".join(process.cmdline())
            except psutil.Error:
                cmdline = ""

            if executable and not self._matches_target_identity(
                f"{process.name()} {executable} {cmdline}".lower(),
                [target["name"]],
                target["executable_paths"] + target["config_paths"] + target["cache_paths"],
            ):
                self._record_preserved(task_id, "process", str(pid), "Skipped process that no longer matches the target.")
                continue

            try:
                process.terminate()
                process.wait(timeout=4)
                self._record_removed(task_id, "process", str(pid), f"Terminated {process.name()}.")
                self._append_log(task_id, f"Terminated process {pid}.")
            except psutil.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
                self._record_removed(task_id, "process", str(pid), f"Killed {process.name()} after timeout.")
                self._append_log(task_id, f"Killed process {pid} after timeout.")
            except psutil.Error as exc:
                self._record_preserved(task_id, "process", str(pid), f"Process termination failed: {exc}")
                self._append_log(task_id, f"Failed to terminate process {pid}: {exc}", level="warning")

    def _step_persistence(self, task_id: str, target: dict[str, Any], plan: dict[str, Any]) -> None:
        if not plan["remove_startup"]:
            self._append_log(task_id, "Startup and persistence cleanup was disabled by request.")
            return
        if not plan["startup_entries"]:
            self._append_log(task_id, "No user-level persistence entries were identified.")
            return

        for entry in plan["startup_entries"]:
            kind = entry.get("kind")
            try:
                if kind == "registry_run":
                    subprocess.check_call(
                        [
                            "reg",
                            "delete",
                            entry["registry_key"],
                            "/v",
                            entry["label"],
                            "/f",
                        ],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=6,
                    )
                    self._record_removed(task_id, "startup", entry["label"], "Removed HKCU Run entry.")
                elif kind == "scheduled_task":
                    subprocess.check_call(
                        [
                            "schtasks",
                            "/delete",
                            "/tn",
                            entry["task_name"],
                            "/f",
                        ],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=8,
                    )
                    self._record_removed(task_id, "startup", entry["label"], "Removed scheduled task.")
                elif entry.get("path"):
                    self._remove_path(
                        task_id,
                        Path(entry["path"]),
                        kind="startup",
                        reason=f"Removing persistence item {entry['label']}",
                    )
                else:
                    self._record_preserved(task_id, "startup", entry.get("label", kind or "unknown"), "Unsupported persistence entry format.")
            except Exception as exc:
                self._record_preserved(task_id, "startup", entry.get("label", kind or "unknown"), f"Persistence cleanup failed: {exc}")
                self._append_log(task_id, f"Persistence cleanup failed for {entry.get('label', kind)}: {exc}", level="warning")

    def _step_clean(self, task_id: str, target: dict[str, Any], plan: dict[str, Any]) -> None:
        if plan["remove_config"]:
            for path in plan["config_paths"]:
                self._remove_path(task_id, Path(path), kind="config", reason="Cleaning config footprint")
        else:
            for path in plan["config_paths"]:
                self._record_preserved(task_id, "config", path, "Config cleanup was disabled by request.")

        if plan["remove_cache"]:
            for path in plan["cache_paths"]:
                self._remove_path(task_id, Path(path), kind="cache", reason="Cleaning cache footprint")
        else:
            for path in plan["cache_paths"]:
                self._record_preserved(task_id, "cache", path, "Cache cleanup was disabled by request.")

        if not plan["config_paths"] and not plan["cache_paths"]:
            self._append_log(task_id, "No config or cache paths were planned for removal.")

    def _step_remove_binaries(self, task_id: str, target: dict[str, Any], plan: dict[str, Any]) -> None:
        if not plan["remove_binary"]:
            for path in plan["binary_paths"]:
                self._record_preserved(task_id, "binary", path, "Binary removal was disabled by request.")
            return
        if not plan["binary_paths"]:
            self._append_log(task_id, "No explicit binary paths were approved for removal.")
            return

        for path in plan["binary_paths"]:
            self._remove_path(task_id, Path(path), kind="binary", reason="Removing core binary file")

    def _step_verify(self, task_id: str, target: dict[str, Any], plan: dict[str, Any]) -> None:
        leftovers = []
        for raw_path in plan["all_paths"]:
            path = Path(raw_path)
            if path.exists():
                leftovers.append({"type": "path", "value": str(path), "reason": "Path still exists after removal pass."})

        for entry in plan["startup_entries"]:
            if entry.get("path"):
                startup_path = Path(entry["path"])
                if startup_path.exists():
                    leftovers.append({"type": "startup", "value": str(startup_path), "reason": "Persistence file still exists."})

        for pid in plan["pids"]:
            if psutil.pid_exists(pid):
                leftovers.append({"type": "process", "value": str(pid), "reason": "Process is still active."})

        with self._lock:
            task = self._tasks[task_id]
            task["leftover_items"] = leftovers
            task["updated_at"] = self._now()

        if leftovers:
            self._append_log(task_id, f"Verification found {len(leftovers)} leftover item(s).", level="warning")
        else:
            self._append_log(task_id, "Verification completed with no remaining approved footprint.")

    def _step_finalize(self, task_id: str, target: dict[str, Any], plan: dict[str, Any]) -> None:
        with self._lock:
            task = self._tasks[task_id]
            removed = len(task["removed_items"])
            preserved = len(task["preserved_items"])
            leftovers = len(task["leftover_items"])
            error = task["error"]

        if removed and not leftovers and not preserved and not error:
            status = "success"
        elif removed or preserved or leftovers:
            status = "partial"
        else:
            status = "failed"

        result = self._build_task_result(task_id, target, status=status)
        self._set_task_state(
            task_id,
            _pending_terminal_state={
                "status": status,
                "finished_at": self._now(),
                "duration_ms": self._task_duration_ms(task_id),
                "result": result,
            },
        )

    def _build_task_result(self, task_id: str, target: dict[str, Any], *, status: str | None = None) -> dict[str, Any]:
        with self._lock:
            task = self._tasks[task_id]
            removed = len(task["removed_items"])
            preserved = len(task["preserved_items"])
            leftovers = len(task["leftover_items"])
            result_status = status or task.get("status")

        blocked_reasons = self._collect_blocked_reasons(task_id, target)
        manual_steps = self._build_manual_steps(task_id, target)
        summary = f"{removed} item(s) removed, {preserved} preserved, {leftovers} leftover."
        if blocked_reasons:
            summary = f"{summary} {blocked_reasons[0]}"
        return {
            "status": result_status,
            "summary": summary,
            "removed_items": removed,
            "preserved_items": preserved,
            "leftover_items": leftovers,
            "manual_review_required": bool(preserved or leftovers or blocked_reasons),
            "blocked_reasons": blocked_reasons,
            "manual_steps": manual_steps,
            "support_level": target.get("support_level"),
            "target_summary": target.get("target_summary"),
            "rationale": target.get("rationale"),
        }

    def _collect_blocked_reasons(self, task_id: str, target: dict[str, Any]) -> list[str]:
        reasons: list[str] = []
        if target.get("blocked_reason_label"):
            reasons.append(f"{target['blocked_reason_label']}: {target.get('unsupported_reason') or target.get('rationale') or 'Manual review is required.'}")

        with self._lock:
            task = self._tasks[task_id]
            items = list(task.get("preserved_items", [])) + list(task.get("leftover_items", []))

        for item in items:
            detail = str(item.get("detail") or item.get("reason") or "").strip()
            if not detail:
                continue
            reasons.append(detail)
        return list(dict.fromkeys(reasons))[:8]

    def _build_manual_steps(self, task_id: str, target: dict[str, Any]) -> list[str]:
        with self._lock:
            task = self._tasks[task_id]
            preserved = list(task.get("preserved_items", []))
            leftovers = list(task.get("leftover_items", []))

        steps: list[str] = []
        if any(item.get("type") == "process" for item in preserved + leftovers):
            steps.append("Confirm the linked process is stopped, then rerun a scan before removing anything else.")
        if any(item.get("type") == "startup" for item in preserved + leftovers):
            steps.append("Review remaining user-level persistence items and remove only entries that still point to the target.")
        if any(item.get("type") in {"binary", "config", "cache", "path"} for item in preserved + leftovers):
            steps.append("Inspect preserved or leftover paths and remove only target-specific files inside the approved footprint.")
        if target.get("blocked_reason_code") in {"path_too_broad", "user_data_overlap", "binary_not_safe_to_remove"}:
            steps.append("Keep binary removal manual because the identified path overlaps a protected or user-data-heavy location.")
        if not steps and target.get("support_level") == "terminate_only":
            steps.append("Contain the target by stopping its process and keep file cleanup under manual review.")
        return list(dict.fromkeys(steps))[:4]

    def _task_duration_ms(self, task_id: str) -> int | None:
        with self._lock:
            task = self._tasks[task_id]
            started_clock = task.get("_started_monotonic")
        if started_clock is None:
            return None
        return int(round((time.perf_counter() - started_clock) * 1000))

    def _build_execution_plan(self, target: dict[str, Any], options: dict[str, Any]) -> dict[str, Any]:
        allowed_roots = self._build_allowed_roots(target)
        forbidden_roots = self._forbidden_roots()
        config_paths, config_rejected = self.filter_removable_paths(
            target.get("config_paths", []),
            kind="config",
            allowed_roots=allowed_roots,
            forbidden_roots=forbidden_roots,
        )
        cache_paths, cache_rejected = self.filter_removable_paths(
            target.get("cache_paths", []),
            kind="cache",
            allowed_roots=allowed_roots,
            forbidden_roots=forbidden_roots,
        )
        binary_paths, binary_rejected = self.filter_removable_paths(
            target.get("executable_paths", []),
            kind="binary",
            allowed_roots=allowed_roots,
            forbidden_roots=forbidden_roots,
        )
        startup_entries = [dict(item) for item in target.get("startup_entries", [])]
        all_paths = list(dict.fromkeys(config_paths + cache_paths + binary_paths))
        rejected_paths = config_rejected + cache_rejected + binary_rejected
        if options.get("remove_binary") and not target.get("remove_binary_allowed"):
            rejected_value = (
                target.get("primary_executable")
                or self._path_from_warning(target.get("path_warnings", []))
                or target.get("primary_workdir")
                or target.get("display_name")
            )
            rejected_paths.append(
                {
                    "type": "binary",
                    "value": rejected_value,
                    "detail": target.get("remove_binary_reason") or "Binary removal was requested, but the path did not pass safety validation.",
                }
            )
        return {
            "pids": [int(pid) for pid in target.get("pids", []) if isinstance(pid, (int, str))],
            "startup_entries": startup_entries,
            "config_paths": config_paths,
            "cache_paths": cache_paths,
            "binary_paths": binary_paths,
            "all_paths": all_paths,
            "allowed_roots": [str(path) for path in allowed_roots],
            "rejected_paths": rejected_paths,
            "remove_startup": bool(options.get("remove_startup")),
            "remove_cache": bool(options.get("remove_cache")),
            "remove_config": bool(options.get("remove_config")),
            "remove_binary": bool(options.get("remove_binary")),
        }

    def _path_from_warning(self, warnings: list[str]) -> str | None:
        for warning in warnings or []:
            if ":" not in warning:
                continue
            _, candidate = warning.split(":", 1)
            text = candidate.strip()
            if text:
                return text
        return None

    def _remove_path(self, task_id: str, path: Path, *, kind: str, reason: str) -> None:
        allowed_roots = [path] if path.is_dir() else [path.parent, path]
        validation_error = self._validate_removal_path(path, kind=kind, allowed_roots=allowed_roots)
        if validation_error:
            self._record_preserved(task_id, kind, str(path), validation_error)
            self._append_log(task_id, f"Skipped {path}: {validation_error}", level="warning")
            return
        if not path.exists():
            self._append_log(task_id, f"Skipped {kind} path {path}: footprint already absent.")
            return

        try:
            if path.is_symlink() or path.is_file():
                self._remove_file(path)
            elif path.is_dir():
                self._remove_directory(task_id, path, kind=kind)
            else:
                raise RuntimeError("Unsupported path type.")
            self._record_removed(task_id, kind, str(path), reason)
            self._append_log(task_id, f"Removed {kind} path: {path}")
        except Exception as exc:
            self._record_preserved(task_id, kind, str(path), f"Removal failed: {exc}")
            self._append_log(task_id, f"Failed to remove {path}: {exc}", level="warning")

    def _remove_file(self, path: Path) -> None:
        path.unlink(missing_ok=True)

    def _remove_directory(self, task_id: str, root: Path, *, kind: str) -> None:
        self._safe_remove_tree(task_id, root, kind=kind)

    def _safe_remove_tree(self, task_id: str, root: Path, *, kind: str) -> None:
        for current_root, dirs, files in os.walk(root, topdown=False, followlinks=False):
            current = Path(current_root)
            for file_name in files:
                child = current / file_name
                if child.is_symlink():
                    safe, reason = self.is_safe_delete_path(
                        child,
                        allowed_roots=[root],
                        forbidden_roots=self._forbidden_roots(),
                        kind=kind,
                    )
                    if safe:
                        child.unlink(missing_ok=True)
                    else:
                        self._record_preserved(task_id, kind, str(child), reason)
                        self._append_log(task_id, f"Skipped linked file {child}: {reason}", level="warning")
                elif child.is_file():
                    child.unlink(missing_ok=True)
            for dir_name in dirs:
                child = current / dir_name
                if child.is_symlink():
                    safe, reason = self.is_safe_delete_path(
                        child,
                        allowed_roots=[root],
                        forbidden_roots=self._forbidden_roots(),
                        kind=kind,
                    )
                    if safe:
                        child.unlink(missing_ok=True)
                    else:
                        self._record_preserved(task_id, kind, str(child), reason)
                        self._append_log(task_id, f"Skipped linked directory {child}: {reason}", level="warning")
                elif child.exists():
                    child.rmdir()
        if root.exists():
            root.rmdir()

    def _run_step(self, task_id: str, index: int, callback) -> None:
        label = UNINSTALL_STEPS[index]
        started = time.perf_counter()
        self._set_task_step(task_id, index, "running")
        try:
            callback()
        except Exception as exc:
            elapsed_ms = int(round((time.perf_counter() - started) * 1000))
            remaining_ms = max(0, MIN_STEP_VISIBLE_MS - elapsed_ms)
            if remaining_ms:
                time.sleep(remaining_ms / 1000)
            elapsed_ms = int(round((time.perf_counter() - started) * 1000))
            self._set_task_step(task_id, index, "failed", duration_ms=elapsed_ms, error=str(exc))
            raise
        elapsed_ms = int(round((time.perf_counter() - started) * 1000))
        remaining_ms = max(0, MIN_STEP_VISIBLE_MS - elapsed_ms)
        if remaining_ms:
            time.sleep(remaining_ms / 1000)
        elapsed_ms = int(round((time.perf_counter() - started) * 1000))
        self._set_task_step(task_id, index, "completed", duration_ms=elapsed_ms)
        progress = int(round(((index + 1) / len(UNINSTALL_STEPS)) * 100))
        self._set_task_state(task_id, progress=progress, current_step=label)
        if index == len(UNINSTALL_STEPS) - 1:
            self._complete_terminal_state(task_id)

    def _build_steps(self) -> list[dict[str, Any]]:
        return [
            {
                "index": index + 1,
                "label": label,
                "status": "pending",
                "started_at": None,
                "finished_at": None,
                "duration_ms": None,
            }
            for index, label in enumerate(UNINSTALL_STEPS)
        ]

    def _set_task_step(self, task_id: str, index: int, status: str, *, duration_ms: int | None = None, error: str | None = None) -> None:
        with self._lock:
            task = self._tasks[task_id]
            step = task["steps"][index]
            now = self._now()
            if status == "running":
                step["started_at"] = now
                task["current_step"] = step["label"]
            if status in {"completed", "failed"}:
                step["finished_at"] = now
                step["duration_ms"] = duration_ms
                if error:
                    step["error"] = error
                task["step_history"].append(
                    {
                        "index": step["index"],
                        "label": step["label"],
                        "status": status,
                        "started_at": step.get("started_at"),
                        "finished_at": now,
                        "duration_ms": duration_ms,
                        "error": error,
                    }
                )
                task["step_history"] = task["step_history"][-40:]
            step["status"] = status
            task["updated_at"] = now

    def _set_task_state(self, task_id: str, **updates: Any) -> None:
        with self._lock:
            task = self._tasks[task_id]
            task.update(updates)
            task["updated_at"] = self._now()

    def _complete_terminal_state(self, task_id: str) -> None:
        with self._lock:
            task = self._tasks[task_id]
            pending = dict(task.get("_pending_terminal_state") or {})
            if not pending:
                return
            task["_pending_terminal_state"] = None
            task["status"] = pending.get("status", task["status"])
            task["progress"] = 100
            task["finished_at"] = pending.get("finished_at") or self._now()
            task["duration_ms"] = pending.get("duration_ms")
            task["result"] = pending.get("result")
            task["_started_monotonic"] = None
            task["updated_at"] = self._now()
            status = task["status"]
        self._append_log(task_id, f"Final status: {status}.")
        self._persist_history()

    def _append_log(self, task_id: str, message: str, *, level: str = "info") -> None:
        with self._lock:
            task = self._tasks[task_id]
            task["logs"].append(
                {
                    "at": self._now(),
                    "level": level,
                    "message": message,
                }
            )
            task["logs"] = task["logs"][-80:]
            task["updated_at"] = self._now()

    def _record_removed(self, task_id: str, item_type: str, value: str, detail: str) -> None:
        with self._lock:
            task = self._tasks[task_id]
            task["removed_items"].append(
                {
                    "type": item_type,
                    "value": value,
                    "detail": detail,
                }
            )
            task["updated_at"] = self._now()

    def _record_preserved(self, task_id: str, item_type: str, value: str, detail: str) -> None:
        with self._lock:
            task = self._tasks[task_id]
            task["preserved_items"].append(
                {
                    "type": item_type,
                    "value": value,
                    "detail": detail,
                }
            )
            task["updated_at"] = self._now()

    def _require_task(self, task_id: str) -> dict[str, Any]:
        with self._lock:
            return self._tasks[task_id]

    def _snapshot_task(self, task: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": task["id"],
            "target_id": task["target_id"],
            "target_name": task["target_name"],
            "target_type": task["target_type"],
            "source_job_id": task.get("source_job_id"),
            "source_scan_id": task.get("source_scan_id"),
            "status": task["status"],
            "created_at": task["created_at"],
            "updated_at": task["updated_at"],
            "started_at": task["started_at"],
            "finished_at": task["finished_at"],
            "duration_ms": task.get("duration_ms"),
            "progress": task["progress"],
            "current_step": task["current_step"],
            "steps": [dict(step) for step in task["steps"]],
            "step_history": [dict(step) for step in task.get("step_history", [])],
            "logs": list(task["logs"]),
            "removed_items": list(task["removed_items"]),
            "preserved_items": list(task["preserved_items"]),
            "leftover_items": list(task["leftover_items"]),
            "error": task["error"],
            "request_options": dict(task["request_options"]),
            "target": dict(task["target"]),
            "result": dict(task["result"]) if isinstance(task["result"], dict) else task["result"],
        }

    def _coerce_path(self, raw_path: str | Path | None) -> Path | None:
        if not raw_path:
            return None
        if isinstance(raw_path, Path):
            path = raw_path
        else:
            cleaned = str(raw_path).strip().strip('"').strip("'")
            if not cleaned:
                return None
            path = Path(cleaned)
        try:
            return path.expanduser().resolve(strict=False)
        except RuntimeError:
            return None

    def _extract_paths(self, evidence: dict[str, Any]) -> list[Path]:
        paths = []
        if isinstance(evidence.get("path"), str):
            path = self._coerce_path(evidence["path"])
            if path:
                paths.append(path)
        for entry in evidence.get("paths") or []:
            path = self._coerce_path(entry)
            if path:
                paths.append(path)
        return paths

    def _infer_process_path(self, process_info: dict[str, Any]) -> Path | None:
        cmdline = str(process_info.get("cmdline") or "").strip()
        if not cmdline:
            return None
        parts = re.findall(r'"[^"]+"|\S+', cmdline)
        parts = [part.strip('"') for part in parts]
        if not parts:
            return None

        first = parts[0].lower()
        interpreter_markers = ("python", "python.exe", "pythonw.exe", "node", "node.exe", "npm", "npx")
        if any(marker in first for marker in interpreter_markers):
            for candidate in parts[1:4]:
                if candidate.startswith("-"):
                    continue
                path = self._coerce_path(candidate)
                if path:
                    return path

        return self._coerce_path(parts[0])

    def _anchor_path(self, raw_path: str | Path | None) -> Path | None:
        path = self._coerce_path(raw_path)
        if not path:
            return None
        for base in self._user_scoped_bases():
            if not self._is_subpath(path, base):
                continue
            rel = path.relative_to(base)
            if not rel.parts:
                return None
            if len(rel.parts) >= 2 and rel.parts[0].lower() in GENERIC_CONTAINER_NAMES:
                return base / rel.parts[0] / rel.parts[1]
            return base / rel.parts[0]
        return None

    def _candidate_anchor_path(self, raw_path: str | Path | None) -> Path | None:
        path = self._coerce_path(raw_path)
        if not path:
            return None
        startup_root = self._windows_startup_root()
        if startup_root and self._is_subpath(path, startup_root):
            return path if path.is_file() else path.parent
        if path.is_file():
            parent = path.parent
            if parent.name.lower() in {"bin", "config", "configs", "cache", "caches", "log", "logs", "temp", "tmp"}:
                grandparent = parent.parent
                if grandparent and grandparent != grandparent.parent:
                    return grandparent
        return self._anchor_path(path)

    def _best_removal_root(self, raw_path: str | Path) -> Path:
        path = self._coerce_path(raw_path)
        if not path:
            return Path(raw_path)
        markers = {"cache", "caches", "config", "configs", "log", "logs", "temp", "tmp"}
        if path.is_dir() and path.name.lower() in markers:
            return path
        if path.is_file():
            lowered_parts = [part.lower() for part in path.parts]
            for index, part in enumerate(lowered_parts):
                if part in markers:
                    return Path(*path.parts[: index + 1])
        anchor = self._anchor_path(path)
        if anchor and self._is_subpath(path, anchor):
            return anchor
        return path

    def _user_scoped_bases(self) -> list[Path]:
        home = Path.home()
        bases: list[Path] = []
        for value in (os.getenv("APPDATA"), os.getenv("LOCALAPPDATA")):
            if value:
                bases.append(Path(value).resolve())
        bases.extend(
            [
                home / ".config",
                home / ".cache",
                home / "Library" / "Application Support",
                home / "Library" / "Caches",
            ]
        )
        return [base for base in bases if base.exists()]

    def normalize_target_paths(self, paths: list[str], *, kind: str) -> list[Path]:
        normalized: list[Path] = []
        for raw_path in paths:
            path = self._coerce_path(raw_path)
            if not path:
                continue
            normalized.append(path if kind == "binary" else self._best_removal_root(path))

        ordered = sorted(set(normalized), key=lambda item: (len(item.parts), str(item).lower()))
        compact: list[Path] = []
        for path in ordered:
            if kind != "binary" and any(path == existing or self._is_subpath(path, existing) for existing in compact):
                continue
            compact = [
                existing
                for existing in compact
                if kind == "binary" or not self._is_subpath(existing, path)
            ]
            compact.append(path)
        return compact

    def filter_removable_paths(
        self,
        paths: list[str],
        *,
        kind: str,
        allowed_roots: list[Path] | None = None,
        forbidden_roots: list[Path] | None = None,
    ) -> tuple[list[str], list[dict[str, str]]]:
        approved: list[str] = []
        rejected: list[dict[str, str]] = []
        for path in self.normalize_target_paths(paths, kind=kind):
            safe, reason = self.is_safe_delete_path(
                path,
                allowed_roots=allowed_roots,
                forbidden_roots=forbidden_roots,
                kind=kind,
            )
            if safe:
                approved.append(str(path))
                continue
            rejected.append(
                {
                    "type": kind,
                    "value": str(path),
                    "detail": reason,
                }
            )
        return list(dict.fromkeys(approved)), rejected

    def is_safe_delete_path(
        self,
        path: str | Path,
        allowed_roots: list[Path] | None,
        forbidden_roots: list[Path] | None,
        *,
        kind: str,
    ) -> tuple[bool, str]:
        normalized = self._coerce_path(path)
        if not normalized:
            return False, "Path could not be normalized safely."
        if not normalized.is_absolute():
            return False, "Path is not absolute."
        if str(normalized) in {"\\", "/"} or self._looks_like_drive_root(normalized):
            return False, "Refusing to delete a filesystem root."
        if self._is_workspace_path(normalized):
            return False, "Refusing to delete inside the protected workspace."
        if normalized == Path.home():
            return False, "Refusing to delete the user home directory."
        if self._is_protected_path(normalized):
            return False, "Path is broader than the uninstall allowlist."
        if self._looks_like_browser_profile(normalized):
            return False, "Browser profile paths are not auto-removed."
        if kind == "binary" and normalized.is_dir():
            return False, "Binary removal only supports explicit files, not broad directories."

        roots = [root for root in (allowed_roots or []) if root]
        if roots and not any(
            normalized == root or self._is_subpath(normalized, root) or self._is_subpath(root, normalized)
            for root in roots
        ):
            return False, "Path is outside the approved target footprint."

        blocked = [root for root in (forbidden_roots or []) if root]
        if any(normalized == root or self._is_subpath(normalized, root) for root in blocked):
            return False, "Path overlaps a forbidden protected location."
        if not any(self._is_subpath(normalized, base) for base in self._user_scoped_bases()):
            return False, "Path is outside user-scoped config/cache install locations."

        if normalized.exists() and normalized.is_symlink():
            target = normalized.resolve(strict=False)
            if roots and not any(target == root or self._is_subpath(target, root) for root in roots):
                return False, "Symlink resolves outside the approved target footprint."

        return True, ""

    def _validate_removal_path(
        self,
        path: Path,
        *,
        kind: str,
        allowed_roots: list[Path] | None = None,
    ) -> str | None:
        safe, reason = self.is_safe_delete_path(
            path,
            allowed_roots=allowed_roots,
            forbidden_roots=self._forbidden_roots(),
            kind=kind,
        )
        return None if safe else reason

    def _build_allowed_roots(self, target: dict[str, Any]) -> list[Path]:
        roots: list[Path] = []
        for raw_path in (
            list(target.get("config_paths", []))
            + list(target.get("cache_paths", []))
            + list(target.get("executable_paths", []))
        ):
            path = self._coerce_path(raw_path)
            if not path:
                continue
            roots.append(path if path.is_dir() else path.parent)
        for raw_path in (target.get("primary_workdir"),):
            path = self._coerce_path(raw_path)
            if path:
                roots.append(path)
        compact: list[Path] = []
        for path in sorted(set(roots), key=lambda item: (len(item.parts), str(item).lower())):
            if any(path == existing or self._is_subpath(path, existing) for existing in compact):
                continue
            compact.append(path)
        return compact

    def _forbidden_roots(self) -> list[Path]:
        home = Path.home()
        forbidden = [root for root in self._protected_roots if root and root != home]
        for segment in PROTECTED_SEGMENTS:
            forbidden.append(home / segment.title())
            forbidden.append(home / segment)
        return [path for path in forbidden if path]

    def _is_protected_path(self, path: Path) -> bool:
        if path.parent == path:
            return True
        protected_roots = [root for root in self._protected_roots if root != Path.home()]
        if any(self._is_subpath(path, root) for root in protected_roots):
            return True
        if self._is_subpath(path, Path.home()):
            rel = path.relative_to(Path.home())
            if not rel.parts:
                return True
            if rel.parts[0].lower() in PROTECTED_SEGMENTS:
                return True
        for base in self._user_scoped_bases():
            if self._is_subpath(path, base):
                rel = path.relative_to(base)
                if len(rel.parts) == 0:
                    return True
                if len(rel.parts) == 1 and rel.parts[0].lower() in {"temp", "tmp"}:
                    return True
        return False

    def _looks_like_drive_root(self, path: Path) -> bool:
        drive = getattr(path, "drive", "")
        if drive:
            return path == Path(f"{drive}\\")
        return False

    def _is_workspace_path(self, path: Path) -> bool:
        workspace = Path(__file__).resolve().parent
        return self._is_subpath(path, workspace)

    def _looks_like_browser_profile(self, path: Path) -> bool:
        lowered = str(path).lower()
        return any(marker in lowered for marker in BROWSER_PROFILE_MARKERS)

    def _looks_like_cache(self, path: Path) -> bool:
        lowered = str(path).lower()
        return any(
            token in lowered
            for token in ("cache", "cached", "temp", "tmp", "logs", "log", "shader")
        )

    def _is_binary_path(self, path: Path) -> bool:
        return path.suffix.lower() in EXECUTABLE_SUFFIXES

    def _sort_paths(self, paths: set[str] | list[str]) -> list[str]:
        normalized = []
        for item in paths:
            path = self._coerce_path(item)
            if path:
                normalized.append(str(path))
        return sorted(set(normalized))

    def _infer_name_values(self, path: Path) -> set[str]:
        names = {path.stem or path.name}
        anchor = self._anchor_path(path)
        if anchor:
            names.add(anchor.name)
        return {self._display_name(name) for name in names if name}

    def _infer_vendor_values(self, path: Path | None, process_name: str | None) -> set[str]:
        values = set()
        if process_name:
            bits = re.split(r"[_\-. ]+", process_name)
            if bits and bits[0]:
                values.add(bits[0].title())
        if path:
            anchor = self._anchor_path(path)
            if anchor:
                values.add(anchor.name.split("-")[0].split("_")[0].title())
        return {value for value in values if value}

    def _infer_target_type(self, text: str, path: Path | None) -> str:
        lowered = text.lower()
        if ".py" in lowered or "python" in lowered:
            return "python-agent"
        if ".js" in lowered or any(token in lowered for token in ("node", "npm", "npx", "pnpm", "yarn")):
            return "node-agent"
        if any(keyword in lowered for keyword in ("agent", "assistant", "cli", "bot")):
            return "cli-agent"
        if path and path.suffix.lower() in {".exe", ".bat", ".cmd"}:
            return "local-tool"
        return "local-tool"

    def _candidate_confidence(
        self,
        candidate: dict[str, Any],
        executable_paths: list[str],
        config_paths: list[str],
        cache_paths: list[str],
        startup_entries: list[dict[str, Any]],
    ) -> float:
        score = 0.2
        if candidate.get("pids"):
            score += 0.16
        if executable_paths:
            score += 0.2
        if config_paths:
            score += 0.14
        if cache_paths:
            score += 0.08
        if startup_entries:
            score += 0.12
        if len(candidate.get("matched_check_ids", [])) >= 2:
            score += 0.08
        if candidate.get("anchors"):
            score += 0.08
        if candidate.get("browser_like"):
            score -= 0.18
        if candidate.get("protected_hit"):
            score -= 0.24
        return round(max(0.0, min(0.99, score)), 2)

    def _pick_target_display_name(self, target: dict[str, Any]) -> str:
        candidates = [
            target.get("display_name"),
            Path(target["primary_executable"]).stem if target.get("primary_executable") else None,
            Path(target["primary_workdir"]).name if target.get("primary_workdir") else None,
            target.get("name"),
        ]
        for value in candidates:
            if value:
                return self._display_name(str(value))
        return "Unknown Target"

    def _pick_primary_executable(self, target: dict[str, Any]) -> str | None:
        if target.get("primary_executable"):
            return str(target["primary_executable"])
        paths = self.normalize_target_paths(target.get("executable_paths", []), kind="binary")
        return str(paths[0]) if paths else None

    def _pick_primary_workdir(self, target: dict[str, Any]) -> str | None:
        if target.get("primary_workdir"):
            path = self._coerce_path(target["primary_workdir"])
            return str(path) if path else None
        executable = self._coerce_path(target.get("primary_executable"))
        if executable and executable.parent:
            return str(executable.parent)
        for path_group in (target.get("config_paths", []), target.get("cache_paths", [])):
            for raw_path in path_group:
                path = self._coerce_path(raw_path)
                if path:
                    anchor = self._anchor_path(path)
                    return str(anchor or path.parent or path)
        return None

    def _calculate_target_confidence(self, target: dict[str, Any]) -> float:
        score = 0.18
        if target.get("pids"):
            score += 0.14
        if target.get("primary_executable"):
            score += 0.18
        if target.get("primary_workdir"):
            score += 0.12
        if target.get("config_paths"):
            score += 0.14
        if target.get("cache_paths"):
            score += 0.08
        if target.get("startup_entries"):
            score += 0.1
        if len(target.get("matched_check_ids", [])) >= 2:
            score += 0.08
        if any(self._looks_like_agent_name(value) for value in (target.get("display_name") or "", target.get("name") or "")):
            score += 0.06
        if target.get("path_warnings"):
            score -= 0.16
        if not (target.get("config_paths") or target.get("cache_paths") or target.get("startup_entries") or target.get("primary_executable")):
            score -= 0.12
        return round(max(0.0, min(0.99, score)), 2)

    def _can_remove_binary(self, target: dict[str, Any]) -> bool:
        executable = self._coerce_path(target.get("primary_executable"))
        if not executable:
            return False
        if float(target.get("confidence") or 0) < FULL_UNINSTALL_THRESHOLD:
            return False
        if executable.is_dir():
            return False
        if self._is_protected_path(executable):
            return False
        if self._looks_like_browser_profile(executable):
            return False
        if self._is_workspace_path(executable):
            return False
        if self._is_subpath(executable, Path.home()):
            rel = executable.relative_to(Path.home())
            if len(rel.parts) <= 1:
                return False
            if rel.parts[0].lower() in PROTECTED_SEGMENTS:
                return False
        return self._validate_removal_path(executable, kind="binary", allowed_roots=[executable.parent, executable]) is None

    def _binary_block_reason(self, target: dict[str, Any]) -> str:
        executable = self._coerce_path(target.get("primary_executable"))
        if not executable:
            return "No explicit primary executable path was identified."
        if float(target.get("confidence") or 0) < FULL_UNINSTALL_THRESHOLD:
            return "Binary removal was disabled because target confidence did not reach the safe threshold."
        reason = self._validate_removal_path(executable, kind="binary", allowed_roots=[executable.parent, executable])
        return reason or "Binary removal remains disabled pending manual review."

    def _build_target_actions(self, target: dict[str, Any]) -> list[str]:
        actions = []
        if target.get("pids"):
            actions.append("Terminate active processes")
        if target.get("startup_entries"):
            actions.append("Remove user persistence entries")
        if target.get("config_paths"):
            actions.append("Remove config footprint")
        if target.get("cache_paths"):
            actions.append("Remove cache footprint")
        if target.get("remove_binary_allowed"):
            actions.append("Remove explicit binary files")
        elif target.get("executable_paths"):
            actions.append("Preserve binary path for manual review")
        if target.get("support_level") == "terminate_only":
            actions.append("Contain runtime process only")
        if target.get("support_level") == "blocked":
            actions.append("Escalate to manual review")
        return actions

    def _build_target_evidence_summary(self, target: dict[str, Any]) -> str:
        parts = [
            f"{len(target.get('matched_check_ids', []))} matched finding(s)",
            f"confidence {int(round(float(target.get('confidence') or 0) * 100))}%",
        ]
        if target.get("primary_executable"):
            parts.append(f"primary executable {Path(target['primary_executable']).name}")
        elif target.get("primary_workdir"):
            parts.append(f"workdir {Path(target['primary_workdir']).name}")
        if target.get("startup_entries"):
            parts.append(f"{len(target['startup_entries'])} persistence item(s)")
        if target.get("path_warnings"):
            parts.append("some paths were preserved by safety rules")
        if target.get("support_level") == "terminate_only":
            parts.append("runtime-only containment")
        elif target.get("support_level") == "blocked" and target.get("blocked_reason_label"):
            parts.append(target["blocked_reason_label"].lower())
        return ". ".join(parts) + "."

    def _build_target_summary(self, target: dict[str, Any]) -> str:
        summary = f"{target.get('display_name') or target.get('name')} is classified as {target.get('support_level') or 'blocked'}."
        if target.get("support_level") == "full":
            return f"{summary} The runner can stop the process, clean persistence, and remove explicit target files."
        if target.get("support_level") == "cleanup":
            return f"{summary} The runner can clean persistence, config, and cache, while preserving the binary path."
        if target.get("support_level") == "terminate_only":
            return f"{summary} Only controlled process termination is safe with the current evidence."
        if target.get("blocked_reason_label"):
            return f"{summary} {target['blocked_reason_label']} prevents auto-removal."
        return f"{summary} Manual review is required before any deletion."

    def _build_target_rationale(self, target: dict[str, Any]) -> str:
        if target.get("support_level") == "full":
            return "Executable, working footprint, and user-scoped cleanup paths all align with the same target identity."
        if target.get("support_level") == "cleanup":
            return target.get("remove_binary_reason") or "Cleanup paths are clear, but binary removal stays outside the safe boundary."
        if target.get("support_level") == "terminate_only":
            return "Process evidence is strong enough to stop the active agent, but file removal would be broader than the verified footprint."
        return target.get("unsupported_reason") or "The inferred footprint was not precise enough for automated removal."

    def _classify_blocked_reason(self, target: dict[str, Any], unsupported_reason: str | None) -> tuple[str | None, str | None, str | None]:
        if not unsupported_reason:
            return None, None, None
        lowered = unsupported_reason.lower()
        warnings = " ".join(target.get("path_warnings", [])).lower()
        binary_reason = str(target.get("remove_binary_reason") or "").lower()

        if "browser profile" in lowered or "browser profile" in warnings or "browser profile" in binary_reason:
            code = "user_data_overlap"
        elif "protected" in lowered or "protected" in warnings or "allowlist" in lowered or "outside the approved target footprint" in lowered:
            code = "path_too_broad"
        elif float(target.get("confidence") or 0) < TARGET_CONFIDENCE_THRESHOLD:
            code = "insufficient_evidence"
        elif "manual review" in binary_reason or "binary removal" in lowered or "binary path" in lowered:
            code = "binary_not_safe_to_remove"
        elif target.get("pids") and not (target.get("config_paths") or target.get("cache_paths") or target.get("startup_entries")):
            code = "process_only_detection"
        else:
            code = "insufficient_evidence"

        return code, self._blocked_reason_label(code), unsupported_reason

    def _blocked_reason_label(self, code: str | None) -> str | None:
        return BLOCKED_REASON_LABELS.get(code)

    def _build_target_identity(
        self,
        *,
        display_name: str,
        primary_executable: str | None,
        primary_workdir: Path | str | None,
    ) -> str:
        bits = [self._normalize_name(display_name)]
        if primary_executable:
            bits.append(self._normalize_name(Path(primary_executable).stem))
        if primary_workdir:
            bits.append(self._normalize_name(Path(primary_workdir).name))
        return "::".join(bit for bit in bits if bit) or uuid.uuid4().hex[:10]

    def _pick_preferred_text(self, left: str | None, right: str | None) -> str | None:
        left_text = str(left or "").strip()
        right_text = str(right or "").strip()
        if not left_text:
            return right_text or None
        if not right_text:
            return left_text
        return right_text if len(right_text) > len(left_text) else left_text

    def _pick_preferred_path(self, left: str | None, right: str | None) -> str | None:
        left_path = self._coerce_path(left)
        right_path = self._coerce_path(right)
        if not left_path:
            return str(right_path) if right_path else None
        if not right_path:
            return str(left_path)
        if len(right_path.parts) > len(left_path.parts):
            return str(right_path)
        return str(left_path)

    def _pick_vendor(self, left: str | None, right: str | None) -> str:
        for value in (left, right):
            if value and value != "Unknown":
                return value
        return left or right or "Unknown"

    def _windows_startup_root(self) -> Path:
        return Path(os.getenv("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"

    def _looks_like_agent_name(self, value: str) -> bool:
        lowered = value.lower()
        return any(token in lowered for token in ("agent", "assistant", "bot", "cli"))

    def _pick_target_type(self, types: set[str]) -> str:
        for value in ("python-agent", "node-agent", "cli-agent", "local-tool"):
            if value in types:
                return value
        return "local-tool"

    def _risk_level(self, score: int) -> str:
        if score >= 90:
            return "critical"
        if score >= 70:
            return "high"
        if score >= 40:
            return "medium"
        return "low"

    def _display_name(self, raw: str) -> str:
        clean = Path(raw).stem if any(char in raw for char in "\\/.") else raw
        clean = re.sub(r"\.(exe|py|js|bat|cmd)$", "", clean, flags=re.IGNORECASE)
        return clean.replace("_", " ").replace("-", " ").strip().title() or clean

    def _normalize_name(self, raw: str) -> str:
        return re.sub(r"[^a-z0-9]+", "-", raw.lower()).strip("-")

    def _matches_target_identity(self, haystack: str, names: list[str], paths: list[str]) -> bool:
        lowered = haystack.lower()
        collapsed = lowered.replace(" ", "").replace("-", "")
        for name in names:
            normalized = self._normalize_name(name)
            if self._is_generic_identity_name(normalized):
                continue
            if normalized and normalized.replace("-", "") in collapsed:
                return True
            if name.lower() in lowered:
                return True
        for path in paths:
            if path and path.lower() in lowered:
                return True
            base = Path(path).name.lower()
            if base and base in lowered:
                return True
        return False

    def _is_generic_identity_name(self, normalized: str) -> bool:
        bits = [bit for bit in normalized.split("-") if bit]
        if not bits:
            return True
        if len(bits) == 1 and bits[0] in GENERIC_IDENTITY_NAMES:
            return True
        return all(bit in GENERIC_IDENTITY_NAMES for bit in bits)

    def _is_subpath(self, child: Path, parent: Path) -> bool:
        try:
            child.relative_to(parent)
            return True
        except ValueError:
            return False

    @staticmethod
    def _now() -> str:
        return dt.datetime.now().isoformat(timespec="seconds")
