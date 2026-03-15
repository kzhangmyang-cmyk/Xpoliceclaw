#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
WITH_WEBVIEW="${WITH_WEBVIEW:-0}"
CLEAN="${CLEAN:-0}"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "build_macos.sh must be run on macOS." >&2
  exit 1
fi

if [[ ! -x "$PYTHON" ]]; then
  echo "Expected virtual environment python at $PYTHON" >&2
  exit 1
fi

pushd "$ROOT" >/dev/null

"$PYTHON" -m pip install -r requirements-desktop.txt pyinstaller
if [[ "$WITH_WEBVIEW" == "1" ]]; then
  "$PYTHON" -m pip install -r requirements-webview.txt
fi

APP_NAME="$("$PYTHON" - <<'PY'
import app_metadata as m
print(m.MACOS_APP_NAME)
PY
)"

if [[ "$CLEAN" == "1" ]]; then
  rm -rf "$ROOT/build/$APP_NAME" "$ROOT/dist/$APP_NAME.app"
fi

"$PYTHON" -m PyInstaller \
  --noconfirm \
  --clean \
  --windowed \
  --name "$APP_NAME" \
  --osx-bundle-identifier "com.xpoliceclaw.policeclaw" \
  --add-data "templates:templates" \
  --add-data "static:static" \
  --add-data "sample_data:sample_data" \
  --add-data "index.html:." \
  client_launcher.py

echo
echo "macOS client bundle created at:"
echo "  $ROOT/dist/$APP_NAME.app"

popd >/dev/null
