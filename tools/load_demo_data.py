from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURE = ROOT / "sample_data" / "demo_fixture.json"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app_runtime import ensure_runtime_layout
from scanner_service import ScanService
from uninstall_service import UninstallService


def load_fixture(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def normalize_name(value: str) -> str:
    return "".join(char.lower() for char in str(value or "") if char.isalnum())


def main() -> None:
    parser = argparse.ArgumentParser(description="Load demo scan history into the Police Claw workbench.")
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE, help="Path to the demo fixture JSON file.")
    parser.add_argument(
        "--skip-uninstall-history",
        action="store_true",
        help="Load only the demo scan report and skip seeded uninstall history.",
    )
    args = parser.parse_args()

    fixture_path = args.fixture if args.fixture.is_absolute() else (ROOT / args.fixture).resolve()
    fixture = load_fixture(fixture_path)

    runtime = ensure_runtime_layout()
    service = ScanService(runtime.reports)
    uninstall_service = UninstallService(service)

    report = fixture.get("report") or {}
    context = fixture.get("context") if isinstance(fixture.get("context"), dict) else None
    demo_label = fixture.get("meta", {}).get("label") or "Demo Fixture"
    job = service.register_report_fixture(report, context=context, demo_label=demo_label)

    print(f"Loaded demo scan: {job.get('scan_id')} ({job.get('id')})")

    if args.skip_uninstall_history:
        print("Skipped demo uninstall history.")
        return

    targets = uninstall_service.list_targets(job.get("id"))
    target_map = {
        normalize_name(target.get("display_name") or target.get("name")): target
        for target in targets
    }
    desired_names = {
        normalize_name(item.get("target_display_name") or item.get("target_name"))
        for item in fixture.get("uninstall_history", [])
        if item.get("target_display_name") or item.get("target_name")
    }
    with uninstall_service._lock:
        stale_ids = [
            task_id
            for task_id, task in uninstall_service._tasks.items()
            if task.get("source_job_id") == job.get("id")
            and normalize_name(task.get("target_name")) in desired_names
        ]
        for task_id in stale_ids:
            uninstall_service._tasks.pop(task_id, None)
    if stale_ids:
        uninstall_service._persist_history()

    existing = {
        (task.get("source_job_id"), task.get("target_id"), task.get("status"))
        for task in uninstall_service.list_uninstall_history()
    }

    seeded = 0
    for item in fixture.get("uninstall_history", []):
        match_key = normalize_name(item.get("target_display_name") or item.get("target_name"))
        target = target_map.get(match_key)
        if not target:
            print(f"Skipped demo uninstall seed for '{item.get('target_display_name')}' because no matching target was inferred.")
            continue
        identity = (job.get("id"), target.get("id"), item.get("status"))
        if identity in existing:
            print(f"Skipped existing demo uninstall seed for {target.get('display_name')}.")
            continue
        uninstall_service.import_history_task(
            target=target,
            status=item.get("status") or "partial",
            removed_items=item.get("removed_items"),
            preserved_items=item.get("preserved_items"),
            leftover_items=item.get("leftover_items"),
            logs=item.get("logs"),
            request_options=item.get("request_options"),
            duration_ms=int(item.get("duration_ms") or 920),
            error=item.get("error"),
        )
        seeded += 1

    print(f"Seeded {seeded} demo uninstall history item(s).")
    print(f"Runtime root: {runtime.root}")
    print("Open the desktop client or http://127.0.0.1:5000 after starting the local app.")


if __name__ == "__main__":
    main()
