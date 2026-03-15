from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from dataclasses import dataclass

from werkzeug.serving import make_server

from app_runtime import DESKTOP_SHELL_ENV, RuntimeLayout, ensure_runtime_layout, is_admin_session
from app_metadata import APP_DISPLAY_NAME, APP_INTERNAL_NAME, APP_VERSION


@dataclass
class LocalServerHandle:
    server: object
    thread: threading.Thread
    host: str
    port: int
    api_token: str

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def stop(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=5)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Launch the Police Claw Windows client.")
    parser.add_argument("--host", default="127.0.0.1", help="Local bind host. Defaults to 127.0.0.1.")
    parser.add_argument("--port", type=int, default=0, help="Bind port. Defaults to an ephemeral local port.")
    parser.add_argument("--browser", action="store_true", help="Open the local workbench in the default browser.")
    parser.add_argument("--check", action="store_true", help="Start the local server, verify /api/health, then exit.")
    parser.add_argument("--debug", action="store_true", help="Enable webview debug mode when available.")
    parser.add_argument("--no-elevate", action="store_true", help="Skip the Windows UAC elevation check.")
    parser.add_argument("--elevated", action="store_true", help=argparse.SUPPRESS)
    return parser.parse_args()


def start_local_server(host: str, port: int) -> LocalServerHandle:
    os.environ[DESKTOP_SHELL_ENV] = "1"
    from web_app import app

    server = make_server(host, port, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, name="PoliceClawServer", daemon=True)
    thread.start()
    return LocalServerHandle(
        server=server,
        thread=thread,
        host=host,
        port=server.server_port,
        api_token=app.config["XPOLICECLAW_API_TOKEN"],
    )


def wait_for_health(base_url: str, api_token: str, timeout_seconds: float = 15.0) -> dict:
    deadline = time.time() + timeout_seconds
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            request = urllib.request.Request(
                f"{base_url}/api/health",
                headers={
                    "Accept": "application/json",
                    "X-PoliceClaw-Token": api_token,
                },
            )
            with urllib.request.urlopen(request, timeout=2.5) as response:
                payload = json.loads(response.read().decode("utf-8"))
            if payload.get("ok"):
                return payload
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            last_error = exc
            time.sleep(0.25)
    raise RuntimeError(f"Local workbench did not become ready in time: {last_error}")


def open_in_browser(url: str) -> None:
    webbrowser.open(url, new=1, autoraise=True)


def launch_webview(url: str, debug: bool) -> bool:
    try:
        import webview
    except ImportError:
        return False

    window = webview.create_window(
        f"{APP_DISPLAY_NAME} {APP_VERSION}",
        url,
        width=1480,
        height=960,
        min_size=(1180, 760),
        text_select=True,
    )
    gui = "edgechromium" if os.name == "nt" else None
    webview.start(gui=gui, debug=debug)
    return window is not None


def run_browser_shell(url: str) -> None:
    open_in_browser(url)
    print(f"{APP_DISPLAY_NAME} is available at {url}")
    print("Press Ctrl+C to stop the local service.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass


def print_runtime_banner(layout: RuntimeLayout, url: str) -> None:
    print(f"{APP_DISPLAY_NAME} {APP_VERSION} ({APP_INTERNAL_NAME})")
    print(f"Runtime root: {layout.root}")
    print(f"Data directory: {layout.data}")
    print(f"Reports directory: {layout.reports}")
    print(f"Workbench URL: {url}")


def ensure_admin_mode(args: argparse.Namespace) -> bool:
    if os.name != "nt" or args.no_elevate or args.check:
        return False
    if args.elevated or is_admin_session():
        return False

    command = subprocess.list2cmdline(sys.argv[1:] + ["--elevated"])
    result = ctypes_shell_execute(command)
    if result <= 32:
        raise RuntimeError("Administrator elevation was declined or unavailable.")
    return True


def ctypes_shell_execute(arguments: str) -> int:
    import ctypes

    return int(ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, arguments, None, 1))


def main() -> int:
    args = parse_args()
    layout = ensure_runtime_layout()
    handle: LocalServerHandle | None = None
    try:
        if ensure_admin_mode(args):
            return 0
        handle = start_local_server(args.host, args.port)
        health = wait_for_health(handle.url, handle.api_token)
        print_runtime_banner(layout, handle.url)
        if args.check:
            print(json.dumps(health, ensure_ascii=False))
            return 0

        if args.browser:
            run_browser_shell(handle.url)
            return 0

        try:
            launched = launch_webview(handle.url, args.debug)
        except Exception as exc:
            print(f"Embedded desktop shell was unavailable, falling back to the browser: {exc}", file=sys.stderr)
            launched = False
        if not launched:
            run_browser_shell(handle.url)
        return 0
    except Exception as exc:
        print(f"Failed to launch Police Claw: {exc}", file=sys.stderr)
        return 1
    finally:
        if handle is not None:
            handle.stop()


if __name__ == "__main__":
    raise SystemExit(main())
