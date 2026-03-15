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
MACOS_APP_NAME = "PoliceClawClientMac"
MACOS_ARCHIVE_NAME = "PoliceClaw-macOS"
PUBLIC_SITE_URL = "https://xpoliceclaw.com"
PUBLIC_RELEASE_TAG = f"v{APP_VERSION}"
PUBLIC_RELEASE_URL = f"https://github.com/kzhangmyang-cmyk/Xpoliceclaw/releases/tag/{PUBLIC_RELEASE_TAG}"
PUBLIC_WINDOWS_DOWNLOAD_URL = "https://github.com/kzhangmyang-cmyk/Xpoliceclaw/releases/latest/download/PoliceClaw-Setup-latest.exe"
PUBLIC_MACOS_DOWNLOAD_URL = f"https://github.com/kzhangmyang-cmyk/Xpoliceclaw/releases/latest/download/{MACOS_ARCHIVE_NAME}-latest.zip"
PUBLIC_WINDOWS_MANIFEST_URL = f"{PUBLIC_SITE_URL}/download/windows/latest/manifest.json"
PUBLIC_MACOS_MANIFEST_URL = f"{PUBLIC_SITE_URL}/download/macos/latest/manifest.json"
PUBLIC_DOWNLOAD_URL = PUBLIC_WINDOWS_DOWNLOAD_URL
PUBLIC_UPDATE_MANIFEST_URL = PUBLIC_WINDOWS_MANIFEST_URL


def version_tuple() -> tuple[int, int, int, int]:
    parts = [int(part) for part in APP_VERSION.split(".")]
    while len(parts) < 4:
        parts.append(0)
    return tuple(parts[:4])
