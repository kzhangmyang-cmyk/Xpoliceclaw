from __future__ import annotations

import os
from pathlib import Path

from flask import Flask, abort, jsonify, render_template, request, send_file, url_for
from werkzeug.exceptions import HTTPException

from scanner_service import ScanService
from uninstall_service import UninstallService


ROOT = Path(__file__).resolve().parent
API_PREFIX = "/api/"


def _prepare_runtime_layout() -> None:
    for directory in (ROOT / "reports", ROOT / "data"):
        directory.mkdir(parents=True, exist_ok=True)


_prepare_runtime_layout()
service = ScanService(ROOT / "reports")
uninstall_service = UninstallService(service)
app = Flask(__name__, template_folder=str(ROOT / "templates"), static_folder=str(ROOT / "static"))


def _decorate_job(job: dict, *, include_report: bool) -> dict:
    payload = dict(job)
    artifacts = dict(payload.get("artifacts", {}))
    if artifacts.get("json"):
        artifacts["json_url"] = url_for("download_artifact", job_id=job["id"], artifact="json")
    if artifacts.get("docx"):
        artifacts["docx_url"] = url_for("download_artifact", job_id=job["id"], artifact="docx")
    payload["artifacts"] = artifacts
    if not include_report:
        payload.pop("report", None)
    return payload


def _decorate_uninstall_task(task: dict) -> dict:
    payload = dict(task)
    payload["result_url"] = url_for("get_uninstall_result", uninstall_id=task["id"])
    return payload


def _is_api_request() -> bool:
    return request.path.startswith(API_PREFIX)


def api_success(payload: dict | None = None, *, status: int = 200):
    body = {"ok": True}
    if payload:
        body.update(payload)
    return jsonify(body), status


def api_error(error: str, *, status: int, message: str | None = None, extra: dict | None = None):
    body = {
        "ok": False,
        "error": error,
        "message": message or error,
    }
    if extra:
        body.update(extra)
    return jsonify(body), status


@app.errorhandler(HTTPException)
def handle_http_exception(exc: HTTPException):
    if not _is_api_request():
        return exc
    message = exc.description if exc.description and exc.description != exc.name else exc.name
    error_code = exc.name.lower().replace(" ", "_")
    return api_error(error_code, status=exc.code or 500, message=message)


@app.errorhandler(Exception)
def handle_api_exception(exc: Exception):
    if not _is_api_request():
        return ("Internal Server Error", 500)
    return api_error("internal_error", status=500, message="Unexpected server error.")


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/architecture")
def architecture():
    arch_path = ROOT / "index.html"
    if not arch_path.exists():
        abort(404, description="Architecture page is not available.")
    return send_file(arch_path)


@app.get("/api/health")
def health():
    active = next((job for job in service.list_jobs() if job["status"] in {"queued", "running"}), None)
    active_uninstall = next(
        (task for task in uninstall_service.list_uninstall_history() if task["status"] in {"pending", "running"}),
        None,
    )
    return api_success(
        {
            "status": "ok",
            "active_job_id": active["id"] if active else None,
            "active_uninstall_id": active_uninstall["id"] if active_uninstall else None,
        }
    )

@app.get("/api/scans")
def list_scans():
    items = [_decorate_job(job, include_report=False) for job in service.list_jobs()]
    return api_success({"items": items})


@app.post("/api/scans")
def create_scan():
    try:
        job, created = service.start_scan()
    except Exception as exc:
        return api_error("scan_start_failed", status=500, message=str(exc))
    status_code = 202 if created else 200
    payload = _decorate_job(job, include_report=True)
    payload["created"] = created
    return api_success(payload, status=status_code)


@app.get("/api/scans/<job_id>")
def get_scan(job_id: str):
    job = service.get_job(job_id, include_report=True)
    if not job:
        abort(404, description="Scan job was not found.")
    return api_success(_decorate_job(job, include_report=True))


@app.get("/api/scans/<job_id>/artifacts/<artifact>")
def download_artifact(job_id: str, artifact: str):
    if artifact not in {"json", "docx"}:
        abort(404, description="Requested artifact type is not supported.")
    path = service.get_artifact_path(job_id, artifact)
    if not path:
        abort(404, description="Requested artifact is not available.")
    return send_file(path, as_attachment=True, download_name=path.name)


@app.get("/api/uninstall/targets")
def list_uninstall_targets():
    job_id = request.args.get("job_id", "").strip() or None
    selected = None
    if job_id:
        selected = service.get_job(job_id, include_report=False, include_context=False)
        if not selected or selected.get("status") != "completed":
            return api_error(
                "invalid_job_id",
                status=400,
                message="job_id must reference a completed scan.",
            )
    latest = selected or service.get_latest_completed_job(include_report=False, include_context=False)
    items = uninstall_service.list_targets(job_id)
    return api_success(
        {
            "items": items,
            "source_scan_id": latest.get("scan_id") if latest else None,
            "source_job_id": latest.get("id") if latest else None,
            "message": None if latest else "No completed scan is available yet.",
        }
    )


@app.post("/api/uninstall")
def create_uninstall():
    payload = request.get_json(silent=True) or {}
    try:
        task, created = uninstall_service.create_uninstall_task(payload)
    except ValueError as exc:
        return api_error("invalid_uninstall_request", status=400, message=str(exc))
    except Exception as exc:
        return api_error("uninstall_create_failed", status=500, message=str(exc))
    response = _decorate_uninstall_task(task)
    response["created"] = created
    return api_success(response, status=202 if created else 200)


@app.get("/api/uninstall/history")
def list_uninstall_history():
    items = [_decorate_uninstall_task(task) for task in uninstall_service.list_uninstall_history()]
    return api_success({"items": items})


@app.get("/api/uninstall/<uninstall_id>")
def get_uninstall_task(uninstall_id: str):
    task = uninstall_service.get_uninstall_task(uninstall_id)
    if not task:
        abort(404, description="Uninstall task was not found.")
    return api_success(_decorate_uninstall_task(task))


@app.get("/api/uninstall/<uninstall_id>/result")
def get_uninstall_result(uninstall_id: str):
    result = uninstall_service.get_uninstall_result(uninstall_id)
    if not result:
        abort(404, description="Uninstall result is not available.")
    return api_success(result)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")), debug=False)
