from __future__ import annotations


APP_ID = "Xpoliceclaw.PoliceClaw"
APP_NAME = "Xpoliceclaw"
APP_DISPLAY_NAME = "Police Claw"
APP_INTERNAL_NAME = "PoliceClawClient"
APP_VERSION = "0.4.0"
APP_PUBLISHER = "Xpoliceclaw"
APP_DESCRIPTION = "Local security scan and remediation workbench for Windows."
APP_COPYRIGHT = "Copyright (c) 2026 Xpoliceclaw"
INSTALL_DIR_NAME = "Xpoliceclaw"
EXECUTABLE_NAME = "PoliceClawClient.exe"


def version_tuple() -> tuple[int, int, int, int]:
    parts = [int(part) for part in APP_VERSION.split(".")]
    while len(parts) < 4:
        parts.append(0)
    return tuple(parts[:4])
