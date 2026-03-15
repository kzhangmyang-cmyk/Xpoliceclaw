from __future__ import annotations

import os
import ctypes
from dataclasses import dataclass
from pathlib import Path

from app_metadata import APP_NAME
RUNTIME_OVERRIDE_ENV = "XPOLICECLAW_RUNTIME_ROOT"
DESKTOP_SHELL_ENV = "XPOLICECLAW_DESKTOP_SHELL"
PROJECT_ROOT = Path(__file__).resolve().parent


@dataclass(frozen=True)
class RuntimeLayout:
    root: Path
    data: Path
    reports: Path
    logs: Path


def resolve_runtime_root() -> Path:
    override = os.getenv(RUNTIME_OVERRIDE_ENV, "").strip()
    if override:
        return Path(override).expanduser().resolve()

    if os.name == "nt":
        local_appdata = os.getenv("LOCALAPPDATA", "").strip()
        if local_appdata:
            return Path(local_appdata).resolve() / APP_NAME
        return (Path.home() / "AppData" / "Local" / APP_NAME).resolve()

    if os.name == "posix" and sys_platform() == "darwin":
        return (Path.home() / "Library" / "Application Support" / APP_NAME).resolve()

    xdg_state = os.getenv("XDG_STATE_HOME", "").strip()
    if xdg_state:
        return (Path(xdg_state).expanduser() / APP_NAME.lower()).resolve()
    return (Path.home() / ".local" / "state" / APP_NAME.lower()).resolve()


def get_runtime_layout() -> RuntimeLayout:
    root = resolve_runtime_root()
    return RuntimeLayout(
        root=root,
        data=root / "data",
        reports=root / "reports",
        logs=root / "logs",
    )


def ensure_runtime_layout() -> RuntimeLayout:
    layout = get_runtime_layout()
    for directory in (layout.root, layout.data, layout.reports, layout.logs):
        directory.mkdir(parents=True, exist_ok=True)
    return layout


def is_desktop_shell() -> bool:
    return os.getenv(DESKTOP_SHELL_ENV, "").strip() == "1"


def is_admin_session() -> bool:
    if os.name != "nt":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def sys_platform() -> str:
    return os.sys.platform
