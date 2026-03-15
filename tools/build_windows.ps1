param(
    [switch]$Clean,
    [switch]$WithWebview
)

$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$python = Join-Path $root ".venv\\Scripts\\python.exe"

if (-not (Test-Path $python)) {
    throw "Expected virtual environment at $python"
}

function Get-ExecutableName {
    & $python -c "import app_metadata as m; print(m.EXECUTABLE_NAME)"
}

Push-Location $root
try {
    $requirementsFile = if ($WithWebview) { "requirements-webview.txt" } else { "requirements-desktop.txt" }
    & $python -m pip install -r $requirementsFile pyinstaller
    $args = @("-m", "PyInstaller", "--noconfirm")
    if ($Clean) {
        $args += "--clean"
    }
    $args += "client_launcher.spec"
    & $python $args
    $exeName = Get-ExecutableName
    Write-Host ""
    Write-Host "Desktop client bundle created at:"
    Write-Host "  $root\\dist\\$exeName"
    if (-not $WithWebview) {
        Write-Host ""
        Write-Host "Native webview support was not bundled. The launcher will fall back to the default browser."
    }
} finally {
    Pop-Location
}
