param(
    [switch]$Clean,
    [switch]$SkipInstaller,
    [switch]$WithWebview
)

$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$python = Join-Path $root ".venv\\Scripts\\python.exe"
$installerScript = Join-Path $root "installer\\PoliceClaw.iss"

if (-not (Test-Path $python)) {
    throw "Expected virtual environment at $python"
}

function Get-AppMetadata {
    $json = & $python -c "import json; import app_metadata as m; print(json.dumps({'app_id': m.APP_ID, 'name': m.APP_DISPLAY_NAME, 'version': m.APP_VERSION, 'publisher': m.APP_PUBLISHER, 'description': m.APP_DESCRIPTION, 'install_dir_name': m.INSTALL_DIR_NAME, 'exe_name': m.EXECUTABLE_NAME}))"
    if (-not $json) {
        throw "Unable to load app metadata."
    }
    return $json | ConvertFrom-Json
}

function Resolve-InnoSetupCompiler {
    $candidates = @(
        (Get-Command ISCC.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue),
        "$env:ProgramFiles(x86)\\Inno Setup 6\\ISCC.exe",
        "$env:ProgramFiles\\Inno Setup 6\\ISCC.exe",
        "$env:LOCALAPPDATA\\Programs\\Inno Setup 6\\ISCC.exe"
    ) | Where-Object { $_ }

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }
    throw "Inno Setup compiler (ISCC.exe) was not found. Install Inno Setup 6 or add ISCC.exe to PATH."
}

Push-Location $root
try {
    $buildArgs = @()
    if ($Clean) {
        $buildArgs += "-Clean"
    }
    if ($WithWebview) {
        $buildArgs += "-WithWebview"
    }
    & (Join-Path $root "tools\\build_windows.ps1") $buildArgs

    $metadata = Get-AppMetadata
    $exePath = Join-Path $root "dist\\$($metadata.exe_name)"
    if (-not (Test-Path $exePath)) {
        throw "Expected bundled executable at $exePath"
    }

    if ($SkipInstaller) {
        Write-Host ""
        Write-Host "Windows client bundle ready at:"
        Write-Host "  $exePath"
        return
    }

    $env:PC_APP_ID = $metadata.app_id
    $env:PC_APP_NAME = $metadata.name
    $env:PC_APP_VERSION = $metadata.version
    $env:PC_APP_PUBLISHER = $metadata.publisher
    $env:PC_APP_DESCRIPTION = $metadata.description
    $env:PC_INSTALL_DIR_NAME = $metadata.install_dir_name
    $env:PC_EXECUTABLE_NAME = $metadata.exe_name
    $env:PC_DIST_ROOT = (Join-Path $root "dist")
    $env:PC_RELEASE_ROOT = (Join-Path $root "dist\\release")

    $iscc = Resolve-InnoSetupCompiler
    & $iscc $installerScript

    $setupPath = Join-Path $root "dist\\release\\PoliceClaw-Setup-$($metadata.version).exe"
    $latestAliasPath = Join-Path $root "dist\\release\\PoliceClaw-Setup-latest.exe"
    Copy-Item -Path $setupPath -Destination $latestAliasPath -Force
    Write-Host ""
    Write-Host "Release bundle created:"
    Write-Host "  Client:   $exePath"
    Write-Host "  Installer: $setupPath"
    Write-Host "  Latest alias: $latestAliasPath"
} finally {
    Pop-Location
}
