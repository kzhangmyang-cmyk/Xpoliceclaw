# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

from app_metadata import (
    APP_COPYRIGHT,
    APP_DESCRIPTION,
    APP_DISPLAY_NAME,
    APP_INTERNAL_NAME,
    APP_PUBLISHER,
    APP_VERSION,
    EXECUTABLE_NAME,
    version_tuple,
)

try:
    from PyInstaller.utils.hooks import collect_submodules
except Exception:
    collect_submodules = None


def write_version_resource(target: Path) -> None:
    major, minor, patch, build = version_tuple()
    payload = f"""
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=({major}, {minor}, {patch}, {build}),
    prodvers=({major}, {minor}, {patch}, {build}),
    mask=0x3F,
    flags=0x0,
    OS=0x4,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable(
        '040904B0',
        [
          StringStruct('CompanyName', '{APP_PUBLISHER}'),
          StringStruct('FileDescription', '{APP_DESCRIPTION}'),
          StringStruct('FileVersion', '{APP_VERSION}'),
          StringStruct('InternalName', '{APP_INTERNAL_NAME}'),
          StringStruct('OriginalFilename', '{EXECUTABLE_NAME}'),
          StringStruct('ProductName', '{APP_DISPLAY_NAME}'),
          StringStruct('ProductVersion', '{APP_VERSION}'),
          StringStruct('LegalCopyright', '{APP_COPYRIGHT}')
        ]
      )
    ]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
""".strip()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(payload, encoding="utf-8")


project_root = Path(SPEC).resolve().parent
version_info = project_root / "build" / "windows_version_info.txt"
write_version_resource(version_info)

datas = [
    (str(project_root / "templates"), "templates"),
    (str(project_root / "static"), "static"),
    (str(project_root / "sample_data"), "sample_data"),
    (str(project_root / "index.html"), "."),
]
if collect_submodules is None:
    hiddenimports = []
else:
    try:
        hiddenimports = collect_submodules("webview")
    except Exception:
        hiddenimports = []


a = Analysis(
    ["client_launcher.py"],
    pathex=[str(project_root)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name=Path(EXECUTABLE_NAME).stem,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version=str(version_info),
)
