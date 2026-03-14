from __future__ import annotations

import datetime as dt
import hashlib
import json
import platform
import threading
import traceback
import uuid
from pathlib import Path
from typing import Any

import police_claw_v3 as core


STAGES = [
    {"key": "queued", "label": "等待开始", "progress": 0},
    {"key": "collect", "label": "采集系统数据", "progress": 14},
    {"key": "traffic", "label": "分析网络流量", "progress": 30},
    {"key": "fs", "label": "扫描文件系统", "progress": 46},
    {"key": "model", "label": "检测模型行为", "progress": 62},
    {"key": "signal", "label": "识别信号并评分", "progress": 82},
    {"key": "report", "label": "生成报告文件", "progress": 96},
    {"key": "completed", "label": "扫描完成", "progress": 100},
]


HISTORY_LIMIT = 50
HISTORY_VERSION = 1
SOURCE_LIVE = "live"
SOURCE_DEMO = "demo"


class ScanService:
    def __init__(self, output_root: Path):
        self.output_root = Path(output_root)
        self.output_root.mkdir(parents=True, exist_ok=True)
        self.data_root = self.output_root.parent / "data"
        self.data_root.mkdir(parents=True, exist_ok=True)
        self.history_path = self.data_root / "scan_history.json"
        self._jobs: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._scan_lock = threading.Lock()
        self._load_history()

    def list_jobs(self) -> list[dict[str, Any]]:
        with self._lock:
            jobs = list(self._jobs.values())

        jobs.sort(key=lambda item: item["created_at"], reverse=True)
        return [self._snapshot(job, include_report=False, include_context=False) for job in jobs]

    def get_job(
        self,
        job_id: str,
        *,
        include_report: bool = True,
        include_context: bool = False,
    ) -> dict[str, Any] | None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return None
            return self._snapshot(
                job,
                include_report=include_report,
                include_context=include_context,
            )

    def get_latest_completed_job(
        self,
        *,
        include_report: bool = True,
        include_context: bool = False,
    ) -> dict[str, Any] | None:
        with self._lock:
            completed = [
                job for job in self._jobs.values()
                if job["status"] == "completed"
            ]
            if not completed:
                return None
            completed.sort(key=lambda item: item["created_at"], reverse=True)
            return self._snapshot(
                completed[0],
                include_report=include_report,
                include_context=include_context,
            )

    def get_artifact_path(self, job_id: str, artifact: str) -> Path | None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return None
            path = job["artifacts"].get(f"{artifact}_path")
        if not path:
            return None
        file_path = Path(path)
        if not file_path.exists():
            return None
        return file_path

    def start_scan(self) -> tuple[dict[str, Any], bool]:
        running = self._get_active_job()
        if running:
            return self._snapshot(running, include_report=True, include_context=False), False

        now = self._now()
        job_id = uuid.uuid4().hex[:10]
        job = {
            "id": job_id,
            "status": "queued",
            "created_at": now,
            "updated_at": now,
            "progress": 0,
            "stage_key": "queued",
            "stage_label": "等待开始",
            "stage_history": [],
            "scan_id": None,
            "stats": {},
            "result_overview": {},
            "report": None,
            "context": None,
            "artifacts": {"json_path": None, "docx_path": None},
            "error": None,
            "traceback": None,
            "source_type": SOURCE_LIVE,
            "demo_label": None,
        }

        with self._lock:
            self._jobs[job_id] = job

        worker = threading.Thread(target=self._run_scan, args=(job_id,), daemon=True)
        worker.start()
        return self._snapshot(job, include_report=True, include_context=False), True

    def register_report_fixture(
        self,
        report: dict[str, Any],
        *,
        context: dict[str, Any] | None = None,
        demo_label: str = "Demo Fixture",
    ) -> dict[str, Any]:
        report_copy = json.loads(json.dumps(report))
        report_copy["demo_mode"] = True
        scan_id = str(report_copy.get("scan_id") or "").strip() or f"DEMO-{uuid.uuid4().hex[:8].upper()}"
        report_copy["scan_id"] = scan_id
        created_at = self._coerce_created_at(report_copy.get("timestamp"))
        output_dir = self.output_root / scan_id.lower().replace(":", "-")
        output_dir.mkdir(parents=True, exist_ok=True)
        json_path = output_dir / "Police_Claw_v3_Report.json"
        json_path.write_text(
            json.dumps(report_copy, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        runtime = report_copy.get("runtime") if isinstance(report_copy.get("runtime"), dict) else {}
        stats = runtime.get("stats") if isinstance(runtime.get("stats"), dict) else {}
        result_overview = runtime.get("result_overview") if isinstance(runtime.get("result_overview"), dict) else {}

        with self._lock:
            existing = next(
                (
                    item for item in self._jobs.values()
                    if item.get("source_type") == SOURCE_DEMO
                    and (
                        item.get("scan_id") == scan_id
                        or item.get("demo_label") == demo_label
                    )
                ),
                None,
            )
            job_id = existing["id"] if existing else uuid.uuid4().hex[:10]
            job = {
                "id": job_id,
                "status": "completed",
                "created_at": created_at,
                "updated_at": self._now(),
                "progress": 100,
                "stage_key": "completed",
                "stage_label": "Demo data loaded",
                "stage_history": [
                    {
                        "key": "completed",
                        "label": "Demo data loaded",
                        "progress": 100,
                        "at": created_at,
                    }
                ],
                "scan_id": scan_id,
                "stats": dict(stats),
                "result_overview": dict(result_overview),
                "report": report_copy,
                "context": context,
                "artifacts": {
                    "json_path": str(json_path),
                    "docx_path": None,
                },
                "error": None,
                "traceback": None,
                "source_type": SOURCE_DEMO,
                "demo_label": demo_label,
            }
            self._jobs[job_id] = job

        self._persist_history()
        return self.get_job(job_id, include_report=True, include_context=True) or {}

    def _get_active_job(self) -> dict[str, Any] | None:
        with self._lock:
            running_jobs = [
                job for job in self._jobs.values()
                if job["status"] in {"queued", "running"}
            ]
            if not running_jobs:
                return None
            running_jobs.sort(key=lambda item: item["created_at"], reverse=True)
            return running_jobs[0]

    def _snapshot(
        self,
        job: dict[str, Any],
        *,
        include_report: bool,
        include_context: bool,
    ) -> dict[str, Any]:
        report = job["report"] if include_report else None
        if include_report and report is None:
            report = self._load_report_from_artifact(job)
        snapshot = {
            "id": job["id"],
            "status": job["status"],
            "created_at": job["created_at"],
            "updated_at": job["updated_at"],
            "progress": job["progress"],
            "stage_key": job["stage_key"],
            "stage_label": job["stage_label"],
            "stage_history": list(job["stage_history"]),
            "scan_id": job["scan_id"],
            "stats": dict(job["stats"]),
            "result_overview": dict(job["result_overview"]),
            "artifacts": {
                "json": bool(job["artifacts"].get("json_path")),
                "docx": bool(job["artifacts"].get("docx_path")),
            },
            "error": job["error"],
            "source_type": job.get("source_type") or SOURCE_LIVE,
            "demo_label": job.get("demo_label"),
            "demo_mode": (job.get("source_type") or SOURCE_LIVE) == SOURCE_DEMO,
        }
        if include_report and report is not None:
            snapshot["report"] = report
        if include_context and job["context"] is not None:
            snapshot["context"] = job["context"]
        return snapshot

    def _update_job(self, job_id: str, **updates: Any) -> dict[str, Any]:
        with self._lock:
            job = self._jobs[job_id]
            job.update(updates)
            job["updated_at"] = self._now()
            stage_key = job.get("stage_key")
            if stage_key and (
                not job["stage_history"] or job["stage_history"][-1]["key"] != stage_key
            ):
                job["stage_history"].append(
                    {
                        "key": stage_key,
                        "label": job.get("stage_label"),
                        "progress": job.get("progress"),
                        "at": job["updated_at"],
                    }
                )
            return self._snapshot(job, include_report=False, include_context=False)

    @staticmethod
    def _collector_context(collector: core.Collector, traffic: dict, fs_data: dict, model_data: dict) -> dict[str, Any]:
        return {
            "collector": {
                "processes": list(collector.processes),
                "connections": list(collector.connections),
                "open_files": list(collector.open_files),
                "dns_servers": list(collector.dns_servers),
                "listening_ports": list(collector.listening_ports),
            },
            "traffic": dict(traffic),
            "fs": dict(fs_data),
            "model": dict(model_data),
        }

    def _refresh_runtime_metadata(self) -> str:
        core.SCAN_TS = dt.datetime.now()
        core.SCAN_ID = hashlib.sha256(
            f"{platform.node()}-{core.SCAN_TS.isoformat()}".encode()
        ).hexdigest()[:12].upper()
        return core.SCAN_ID

    def _run_scan(self, job_id: str) -> None:
        try:
            with self._scan_lock:
                scan_id = self._refresh_runtime_metadata()
                output_dir = self.output_root / scan_id.lower()
                self._update_job(
                    job_id,
                    status="running",
                    scan_id=scan_id,
                    stage_key="collect",
                    stage_label="采集系统数据",
                    progress=14,
                )

                collector = core.Collector().collect_all()
                stats = {
                    "processes": len(collector.processes),
                    "connections": len(collector.connections),
                    "open_files": len(collector.open_files),
                    "env_signals": len(collector.env_signals),
                    "dns_servers": collector.dns_servers,
                    "listening_ports": len(collector.listening_ports),
                }
                self._update_job(job_id, stats=stats)

                self._update_job(
                    job_id,
                    stage_key="traffic",
                    stage_label="分析网络流量",
                    progress=30,
                )
                traffic = core.TrafficMonitor(collector).analyze()
                stats.update(
                    {
                        "outbound_count": traffic["outbound_count"],
                        "cloud_endpoints": len(traffic["cloud_endpoints"]),
                        "model_api_endpoints": len(traffic["model_api_endpoints"]),
                    }
                )
                self._update_job(job_id, stats=stats)

                self._update_job(
                    job_id,
                    stage_key="fs",
                    stage_label="扫描文件系统",
                    progress=46,
                )
                fs_data = core.FSMonitor(collector).analyze()
                stats["fs_zones_hit"] = sum(1 for items in fs_data.values() if items)
                self._update_job(job_id, stats=stats)

                self._update_job(
                    job_id,
                    stage_key="model",
                    stage_label="检测模型行为",
                    progress=62,
                )
                model_data = core.ModelMonitor(collector, traffic).analyze()
                stats.update(
                    {
                        "model_processes": len(model_data["model_procs"]),
                        "embedding_processes": len(model_data["embedding_procs"]),
                        "prompt_files": len(model_data["prompt_files"]),
                    }
                )
                self._update_job(job_id, stats=stats)

                self._update_job(
                    job_id,
                    stage_key="signal",
                    stage_label="识别信号并评分",
                    progress=82,
                )
                signals = core.SignalEngine(collector, traffic, fs_data, model_data).analyze()
                results = core.RiskEngine().evaluate(signals)
                result_overview = {
                    "active_signals": sum(1 for evidence in signals.values() if evidence),
                    "risk_count": sum(
                        1 for item in results
                        if item["detected"] and item["id"] != "audit_system"
                    ),
                    "max_risk_score": max((item["risk_score"] for item in results), default=0),
                }
                self._update_job(job_id, result_overview=result_overview)

                self._update_job(
                    job_id,
                    stage_key="report",
                    stage_label="生成报告文件",
                    progress=96,
                )
                writer = core.ReportWriter(results, output_dir)
                json_path = Path(writer.write_json())
                docx_path = writer.write_docx()

                report = json.loads(json_path.read_text(encoding="utf-8"))
                report["runtime"] = {
                    "stats": stats,
                    "result_overview": result_overview,
                }
                json_path.write_text(
                    json.dumps(report, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )

                self._update_job(
                    job_id,
                    status="completed",
                    stage_key="completed",
                    stage_label="扫描完成",
                    progress=100,
                    report=report,
                    context=self._collector_context(collector, traffic, fs_data, model_data),
                    artifacts={
                        "json_path": str(json_path),
                        "docx_path": str(docx_path) if docx_path else None,
                    },
                )
                self._persist_history()
        except Exception as exc:
            self._update_job(
                job_id,
                status="failed",
                stage_key="completed",
                stage_label="扫描失败",
                error=str(exc),
                traceback=traceback.format_exc(),
            )
            self._persist_history()

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
            job = self._restore_job(item)
            if job:
                restored[job["id"]] = job
        with self._lock:
            self._jobs.update(restored)

    def _persist_history(self) -> None:
        with self._lock:
            items = [
                self._serialize_job_for_history(job)
                for job in self._jobs.values()
                if job["status"] in {"completed", "failed"}
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

    def _serialize_job_for_history(self, job: dict[str, Any]) -> dict[str, Any]:
        report = job.get("report") or self._load_report_from_artifact(job)
        return {
            "id": job["id"],
            "status": job["status"],
            "created_at": job["created_at"],
            "updated_at": job["updated_at"],
            "progress": job["progress"],
            "stage_key": job["stage_key"],
            "stage_label": job["stage_label"],
            "stage_history": list(job.get("stage_history", [])),
            "scan_id": job.get("scan_id"),
            "stats": dict(job.get("stats", {})),
            "result_overview": dict(job.get("result_overview", {})),
            "artifacts": {
                "json_path": job.get("artifacts", {}).get("json_path"),
                "docx_path": job.get("artifacts", {}).get("docx_path"),
            },
            "error": job.get("error"),
            "traceback": job.get("traceback"),
            "source_type": job.get("source_type") or SOURCE_LIVE,
            "demo_label": job.get("demo_label"),
            "report_meta": {
                "host": report.get("host") if isinstance(report, dict) else None,
                "os": report.get("os") if isinstance(report, dict) else None,
                "timestamp": report.get("timestamp") if isinstance(report, dict) else None,
                "summary": report.get("summary") if isinstance(report, dict) else None,
                "demo_mode": report.get("demo_mode") if isinstance(report, dict) else None,
            },
        }

    def _restore_job(self, item: dict[str, Any]) -> dict[str, Any] | None:
        job_id = str(item.get("id") or "").strip()
        if not job_id:
            return None
        artifacts = item.get("artifacts") if isinstance(item.get("artifacts"), dict) else {}
        report = self._load_report_from_artifact({"artifacts": artifacts, "report": None})
        if report is None and isinstance(item.get("report_meta"), dict):
            report = {
                "host": item["report_meta"].get("host"),
                "os": item["report_meta"].get("os"),
                "timestamp": item["report_meta"].get("timestamp"),
                "summary": item["report_meta"].get("summary") or {},
                "checks": [],
                "demo_mode": bool(item["report_meta"].get("demo_mode")),
                "runtime": {
                    "stats": item.get("stats", {}),
                    "result_overview": item.get("result_overview", {}),
                },
            }
        return {
            "id": job_id,
            "status": item.get("status") or "completed",
            "created_at": item.get("created_at") or self._now(),
            "updated_at": item.get("updated_at") or item.get("created_at") or self._now(),
            "progress": int(item.get("progress") or 100),
            "stage_key": item.get("stage_key") or "completed",
            "stage_label": item.get("stage_label") or "Completed",
            "stage_history": list(item.get("stage_history") or []),
            "scan_id": item.get("scan_id"),
            "stats": dict(item.get("stats") or {}),
            "result_overview": dict(item.get("result_overview") or {}),
            "report": report,
            "context": None,
            "artifacts": {
                "json_path": artifacts.get("json_path"),
                "docx_path": artifacts.get("docx_path"),
            },
            "error": item.get("error"),
            "traceback": item.get("traceback"),
            "source_type": item.get("source_type") or SOURCE_LIVE,
            "demo_label": item.get("demo_label"),
        }

    def _load_report_from_artifact(self, job: dict[str, Any]) -> dict[str, Any] | None:
        artifacts = job.get("artifacts") if isinstance(job.get("artifacts"), dict) else {}
        json_path = artifacts.get("json_path")
        if not json_path:
            return None
        path = Path(json_path)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None

    def _write_json_atomic(self, path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = path.with_suffix(f"{path.suffix}.tmp")
        temp_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        temp_path.replace(path)

    def _coerce_created_at(self, value: Any) -> str:
        text = str(value or "").strip()
        if not text:
            return self._now()
        normalized = text.replace(" ", "T")
        try:
            return dt.datetime.fromisoformat(normalized).isoformat(timespec="seconds")
        except ValueError:
            return self._now()

    @staticmethod
    def _now() -> str:
        return dt.datetime.now().isoformat(timespec="seconds")
