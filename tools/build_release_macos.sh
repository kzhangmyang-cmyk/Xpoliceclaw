#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
WITH_WEBVIEW="${WITH_WEBVIEW:-0}"
CLEAN="${CLEAN:-0}"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "build_release_macos.sh must be run on macOS." >&2
  exit 1
fi

if [[ ! -x "$PYTHON" ]]; then
  echo "Expected virtual environment python at $PYTHON" >&2
  exit 1
fi

if [[ "$WITH_WEBVIEW" == "1" ]]; then
  WITH_WEBVIEW=1 CLEAN="$CLEAN" "$ROOT/tools/build_macos.sh"
else
  CLEAN="$CLEAN" "$ROOT/tools/build_macos.sh"
fi

VERSION="$("$PYTHON" - <<'PY'
import app_metadata as m
print(m.APP_VERSION)
PY
)"

APP_NAME="$("$PYTHON" - <<'PY'
import app_metadata as m
print(m.MACOS_APP_NAME)
PY
)"

ARCHIVE_BASE="$("$PYTHON" - <<'PY'
import app_metadata as m
print(m.MACOS_ARCHIVE_NAME)
PY
)"

APP_PATH="$ROOT/dist/$APP_NAME.app"
RELEASE_DIR="$ROOT/dist/release"
VERSION_ARCHIVE="$RELEASE_DIR/$ARCHIVE_BASE-$VERSION.zip"
LATEST_ARCHIVE="$RELEASE_DIR/$ARCHIVE_BASE-latest.zip"
MANIFEST_PATH="$ROOT/docs/download/macos/latest/manifest.json"

mkdir -p "$RELEASE_DIR"
ditto -c -k --sequesterRsrc --keepParent "$APP_PATH" "$VERSION_ARCHIVE"
cp "$VERSION_ARCHIVE" "$LATEST_ARCHIVE"

SIZE_BYTES="$(stat -f%z "$LATEST_ARCHIVE")"
export POLICE_CLAW_MACOS_MANIFEST_PATH="$MANIFEST_PATH"
export POLICE_CLAW_MACOS_VERSION="$VERSION"
export POLICE_CLAW_MACOS_ARCHIVE_NAME="$(basename "$LATEST_ARCHIVE")"
export POLICE_CLAW_MACOS_SIZE="$SIZE_BYTES"

"$PYTHON" - <<'PY'
import json
import os
from pathlib import Path

manifest = {
    "platform": "macos",
    "available": True,
    "app_name": "Police Claw",
    "version": os.environ["POLICE_CLAW_MACOS_VERSION"],
    "release_tag": f"v{os.environ['POLICE_CLAW_MACOS_VERSION']}",
    "release_url": f"https://github.com/kzhangmyang-cmyk/Xpoliceclaw/releases/tag/v{os.environ['POLICE_CLAW_MACOS_VERSION']}",
    "download_url": "https://github.com/kzhangmyang-cmyk/Xpoliceclaw/releases/latest/download/PoliceClaw-macOS-latest.zip",
    "installer_filename": os.environ["POLICE_CLAW_MACOS_ARCHIVE_NAME"],
    "installer_size_bytes": int(os.environ["POLICE_CLAW_MACOS_SIZE"]),
    "published_at": __import__("datetime").datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
    "minimum_os": "macOS 13",
    "channel": "preview",
    "status": "available",
    "notes": [
        "Runs the local Police Claw workbench on macOS and stores reports and history under Application Support.",
        "Automatic handling remains conservative and preserves broad, ambiguous, or user-data-heavy targets for manual review.",
        "Upload both the versioned archive and PoliceClaw-macOS-latest.zip to GitHub Releases so the website can publish a stable download path."
    ],
}

path = Path(os.environ["POLICE_CLAW_MACOS_MANIFEST_PATH"])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
PY

echo
echo "macOS release bundle created:"
echo "  Versioned archive: $VERSION_ARCHIVE"
echo "  Latest alias:      $LATEST_ARCHIVE"
echo "  Public manifest:   $MANIFEST_PATH"
