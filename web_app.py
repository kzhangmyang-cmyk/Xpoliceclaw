from __future__ import annotations

import os
import secrets
from pathlib import Path

from flask import Flask, abort, jsonify, render_template, request, send_file, url_for
from werkzeug.exceptions import HTTPException

from app_runtime import PROJECT_ROOT, ensure_runtime_layout, is_admin_session, is_desktop_shell
from app_metadata import APP_DISPLAY_NAME, APP_VERSION
from scanner_service import ScanService
from uninstall_service import UninstallService


ROOT = PROJECT_ROOT
API_PREFIX = "/api/"
LOCAL_API_HEADER = "X-PoliceClaw-Token"
LOCAL_API_QUERY_PARAM = "token"
LOCALHOST_ADDRESSES = {"127.0.0.1", "::1"}
DIST_ROOT = ROOT / "dist"
DEFAULT_RELEASE_ROOT = DIST_ROOT / "release"
RELEASE_ROOT = Path(os.getenv("XPOLICECLAW_RELEASE_ROOT", str(DEFAULT_RELEASE_ROOT))).expanduser()
RUNTIME = ensure_runtime_layout()
service = ScanService(RUNTIME.reports)
uninstall_service = UninstallService(service)
app = Flask(__name__, template_folder=str(ROOT / "templates"), static_folder=str(ROOT / "static"))
app.config.update(
    XPOLICECLAW_RUNTIME_ROOT=str(RUNTIME.root),
    XPOLICECLAW_DATA_ROOT=str(RUNTIME.data),
    XPOLICECLAW_REPORT_ROOT=str(RUNTIME.reports),
    XPOLICECLAW_API_TOKEN=os.getenv("XPOLICECLAW_API_TOKEN", "").strip() or secrets.token_urlsafe(32),
    XPOLICECLAW_DESKTOP_SHELL=is_desktop_shell(),
    XPOLICECLAW_ADMIN_MODE=is_admin_session(),
    XPOLICECLAW_APP_NAME=APP_DISPLAY_NAME,
    XPOLICECLAW_APP_VERSION=APP_VERSION,
    XPOLICECLAW_RELEASE_ROOT=str(RELEASE_ROOT),
)


def _decorate_job(job: dict, *, include_report: bool) -> dict:
    payload = dict(job)
    artifacts = dict(payload.get("artifacts", {}))
    if artifacts.get("json"):
        artifacts["json_url"] = _build_artifact_url(job["id"], "json")
    if artifacts.get("docx"):
        artifacts["docx_url"] = _build_artifact_url(job["id"], "docx")
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


def _is_local_request() -> bool:
    addresses = [
        (address or "").split("%", 1)[0].strip().lower()
        for address in [*request.access_route, request.remote_addr]
        if address
    ]
    if not addresses:
        return True
    return all(address in LOCALHOST_ADDRESSES or address == "localhost" for address in addresses)


def _resolve_client_token() -> str:
    header_token = request.headers.get(LOCAL_API_HEADER, "").strip()
    if header_token:
        return header_token
    return request.args.get(LOCAL_API_QUERY_PARAM, "").strip()


def _build_artifact_url(job_id: str, artifact: str) -> str:
    return url_for(
        "download_artifact",
        job_id=job_id,
        artifact=artifact,
        **{LOCAL_API_QUERY_PARAM: app.config["XPOLICECLAW_API_TOKEN"]},
    )


def _latest_windows_installer() -> dict | None:
    candidates = sorted(RELEASE_ROOT.glob("PoliceClaw-Setup-*.exe"), key=lambda item: item.stat().st_mtime, reverse=True)
    if not candidates:
        return None
    installer = candidates[0]
    version = installer.stem.replace("PoliceClaw-Setup-", "", 1).strip() or APP_VERSION
    return {
        "path": installer,
        "filename": installer.name,
        "version": version,
        "size_bytes": installer.stat().st_size,
        "download_url": url_for("download_windows_installer"),
    }


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


@app.before_request
def enforce_local_api_guardrails():
    if not _is_api_request():
        return None
    if not _is_local_request():
        return api_error("forbidden", status=403, message="Police Claw API accepts local requests only.")
    if _resolve_client_token() != app.config["XPOLICECLAW_API_TOKEN"]:
        return api_error("unauthorized", status=401, message="Missing or invalid local client token.")
    return None


@app.context_processor
def inject_client_bootstrap():
    installer = _latest_windows_installer()
    public_site_mode = not _is_local_request() and not bool(app.config["XPOLICECLAW_DESKTOP_SHELL"])
    return {
        "client_bootstrap": {
            "apiHeaderName": LOCAL_API_HEADER,
            "apiToken": app.config["XPOLICECLAW_API_TOKEN"],
            "desktopShell": bool(app.config["XPOLICECLAW_DESKTOP_SHELL"]),
            "adminMode": bool(app.config["XPOLICECLAW_ADMIN_MODE"]),
            "runtimeRoot": app.config["XPOLICECLAW_RUNTIME_ROOT"],
            "publicSiteMode": public_site_mode,
            "requestIsLocal": _is_local_request(),
            "download": {
                "available": bool(installer),
                "url": installer["download_url"] if installer else "",
                "filename": installer["filename"] if installer else "",
                "version": installer["version"] if installer else "",
                "sizeBytes": installer["size_bytes"] if installer else 0,
            },
        }
    }


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/architecture")
def architecture():
    arch_path = ROOT / "index.html"
    if not arch_path.exists():
        abort(404, description="Architecture page is not available.")
    return send_file(arch_path)


@app.get("/download/windows/latest")
def download_windows_installer():
    installer = _latest_windows_installer()
    if not installer:
        abort(404, description="Windows installer is not available.")
    return send_file(
        installer["path"],
        as_attachment=True,
        download_name=installer["filename"],
        mimetype="application/vnd.microsoft.portable-executable",
    )


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
            "runtime_root": app.config["XPOLICECLAW_RUNTIME_ROOT"],
            "data_root": app.config["XPOLICECLAW_DATA_ROOT"],
            "reports_root": app.config["XPOLICECLAW_REPORT_ROOT"],
            "release_root": app.config["XPOLICECLAW_RELEASE_ROOT"],
            "desktop_shell": bool(app.config["XPOLICECLAW_DESKTOP_SHELL"]),
            "admin_mode": bool(app.config["XPOLICECLAW_ADMIN_MODE"]),
            "app_name": app.config["XPOLICECLAW_APP_NAME"],
            "app_version": app.config["XPOLICECLAW_APP_VERSION"],
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


def run_app(*, host: str | None = None, port: int | None = None, debug: bool = False) -> None:
    resolved_host = host or os.getenv("XPOLICECLAW_HOST", "127.0.0.1")
    resolved_port = int(port or os.getenv("PORT", os.getenv("XPOLICECLAW_PORT", "5000")))
    app.run(host=resolved_host, port=resolved_port, debug=debug)


if __name__ == "__main__":
    run_app(debug=False)
