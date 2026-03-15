# Police Claw Workbench

Police Claw, also called `Xpoliceclaw`, is a local security scan and remediation workbench built around the existing `police_claw_v3.py` engine.

The current project supports:

- real local background scans
- report workbench rendering in HTML/CSS/JS
- JSON and DOCX report export
- conservative uninstall target inference
- background uninstall tasks with progress and residual review
- persisted scan and uninstall history
- a Windows desktop client shell that hosts the existing local workbench

This project is intentionally conservative. It is designed to explain, contain, and clean up clearly scoped user-level footprints, not to behave like an unrestricted remover.

## Architecture

The stack stays close to the existing implementation:

- `police_claw_v3.py`
  Original single-file scan engine and report writer
- `scanner_service.py`
  Background scan orchestration, report persistence, and history restore
- `uninstall_service.py`
  Target inference, uninstall task state machine, persistence cleanup, and path safety checks
- `web_app.py`
  Thin Flask entrypoint and JSON API layer for the local workbench
- `app_runtime.py`
  Runtime directory resolution for desktop and local development
- `client_launcher.py`
  Windows desktop launcher that starts the local Flask server and opens the workbench in `pywebview`
- `templates/index.html`
  Server-rendered workbench shell
- `static/app.js`
  Polling, state management, rendering, and uninstall workflow
- `static/styles.css`
  Shared workbench styling

## Quick Start

### Requirements

- Windows 10 or later for the desktop client flow
- Python `3.11+`
- a local environment where `psutil` can inspect basic system state

### Development Install

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install --upgrade pip
.\.venv\Scripts\python -m pip install -r requirements.txt
```

### Desktop Client Install

```powershell
.\.venv\Scripts\python -m pip install -r requirements-desktop.txt
```

Optional native embedded shell dependency:

```powershell
.\.venv\Scripts\python -m pip install -r requirements-webview.txt
```

### Run The Local Workbench

For browser-based local development:

```powershell
.\.venv\Scripts\python web_app.py
```

Default address:

- [http://127.0.0.1:5000](http://127.0.0.1:5000)

For the Windows desktop client shell:

```powershell
.\.venv\Scripts\python client_launcher.py
```

The desktop launcher starts a local-only Flask server on `127.0.0.1`, requests Windows administrator elevation by default, and then opens the existing workbench UI in `pywebview`. If `pywebview` is unavailable, it falls back to the default browser.

For development-only runs without the UAC prompt:

```powershell
.\.venv\Scripts\python client_launcher.py --no-elevate
```

### Build A Windows Client Bundle

```powershell
.\tools\build_windows.ps1
```

This uses `client_launcher.spec` and PyInstaller to produce `dist\PoliceClawClient.exe`.

To try bundling the embedded `pywebview` shell as well:

```powershell
.\tools\build_windows.ps1 -WithWebview
```

If `pywebview` cannot be bundled in the current environment, the launcher still works and falls back to the default browser.

### Build A Windows Installer

Requirements:

- Inno Setup 6

```powershell
.\tools\build_release.ps1
```

This builds the desktop executable first, then compiles `installer\PoliceClaw.iss` into `dist\release\PoliceClaw-Setup-<version>.exe`.

If the Flask app is hosted as a website, the latest installer can be served directly from:

- `/download/windows/latest`

Optional:

```powershell
.\tools\build_release.ps1 -WithWebview
```

The release build now also creates a stable alias:

- `dist\release\PoliceClaw-Setup-latest.exe`

That alias is meant for GitHub Releases so the website can always point to the latest installer with a stable filename.

## GitHub Pages Delivery

The lowest-maintenance public deployment model for this repository is:

- GitHub Pages for `xpoliceclaw.com`
- GitHub Releases for the Windows installer binaries
- Dynadot DNS for the custom domain

Repository assets for this path:

- `docs/index.html`
- `docs/download/windows/latest/index.html`
- `docs/architecture/index.html`
- `docs/CNAME`

### Publish The Website

1. In GitHub, open repository settings.
2. Enable GitHub Pages.
3. Set the publishing source to `Deploy from a branch`.
4. Select the `main` branch and the `/docs` folder.
5. Save and wait for the site to publish.

### Publish The Installer

After running:

```powershell
.\tools\build_release.ps1
```

upload these release assets to a GitHub Release:

- `dist\release\PoliceClaw-Setup-<version>.exe`
- `dist\release\PoliceClaw-Setup-latest.exe`

The public site uses the stable alias at:

```text
https://github.com/kzhangmyang-cmyk/Xpoliceclaw/releases/latest/download/PoliceClaw-Setup-latest.exe
```

### Dynadot + GitHub Pages

Configure `xpoliceclaw.com` to point at GitHub Pages, then keep `docs/CNAME` committed as:

```text
xpoliceclaw.com
```

GitHub Pages custom domain setup:

- [About custom domains and GitHub Pages](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/about-custom-domains-and-github-pages)
- [Managing a custom domain for your GitHub Pages site](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/managing-a-custom-domain-for-your-github-pages-site)

At Dynadot, switch the domain to `Dynadot DNS`, then create the records GitHub Pages expects for an apex domain and `www`.

Recommended records for `xpoliceclaw.com`:

- `A` `@` -> `185.199.108.153`
- `A` `@` -> `185.199.109.153`
- `A` `@` -> `185.199.110.153`
- `A` `@` -> `185.199.111.153`
- optional `AAAA` `@` -> `2606:50c0:8000::153`
- optional `AAAA` `@` -> `2606:50c0:8001::153`
- optional `AAAA` `@` -> `2606:50c0:8002::153`
- optional `AAAA` `@` -> `2606:50c0:8003::153`
- `CNAME` `www` -> `kzhangmyang-cmyk.github.io`

Dynadot DNS management reference:

- [Set DNS for your domain](https://www.dynadot.com/help/question/set-up-DNS)

### Public URLs

After Pages and DNS are configured:

- `https://xpoliceclaw.com/`
- `https://xpoliceclaw.com/download/windows/latest/`
- `https://xpoliceclaw.com/architecture/`

The public site is download-only. Real scan and uninstall actions still run only inside the installed Windows client.

## Deploy `xpoliceclaw.com`

The public website should be treated as a download and documentation site.

- remote visitors can browse the workbench shell in website mode
- the website can distribute the latest Windows installer from `/download/windows/latest`
- real scan and uninstall actions still run only inside the installed Windows client

### Recommended Server Shape

Use a small Ubuntu VPS with:

- Nginx
- Python `3.11+`
- a virtual environment with `requirements-server.txt`
- a writable release directory for the Windows installer

The repository includes deployment templates:

- `requirements-server.txt`
- `deploy/systemd/xpoliceclaw-site.service.example`
- `deploy/nginx/xpoliceclaw.conf.example`

### Server Layout

Example production paths:

```text
/opt/xpoliceclaw/app
/var/lib/xpoliceclaw/runtime
/var/lib/xpoliceclaw/releases
```

Suggested meaning:

- `/opt/xpoliceclaw/app`
  application checkout
- `/var/lib/xpoliceclaw/runtime`
  runtime data, reports, and logs used by local-only maintenance runs
- `/var/lib/xpoliceclaw/releases`
  Windows installer files served by `/download/windows/latest`

### Deploy Steps

1. Copy the repository to the server.
2. Create a Python virtual environment.
3. Install server dependencies.
4. Copy the latest Windows installer into the release directory.
5. Install the provided systemd and Nginx templates.
6. Point Dynadot DNS at the VPS.
7. Issue TLS with Certbot.

Example commands on Ubuntu:

```bash
sudo mkdir -p /opt/xpoliceclaw/app /var/lib/xpoliceclaw/runtime /var/lib/xpoliceclaw/releases
sudo chown -R $USER:$USER /opt/xpoliceclaw/app
git clone https://github.com/kzhangmyang-cmyk/Xpoliceclaw.git /opt/xpoliceclaw/app
cd /opt/xpoliceclaw/app
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -r requirements-server.txt
```

Upload the installer produced on Windows:

```bash
scp dist/release/PoliceClaw-Setup-0.4.0.exe user@your-server:/var/lib/xpoliceclaw/releases/
```

The public Flask process should use:

```bash
XPOLICECLAW_HOST=127.0.0.1
XPOLICECLAW_PORT=8000
XPOLICECLAW_RUNTIME_ROOT=/var/lib/xpoliceclaw/runtime
XPOLICECLAW_RELEASE_ROOT=/var/lib/xpoliceclaw/releases
```

Then install the templates:

```bash
sudo cp deploy/systemd/xpoliceclaw-site.service.example /etc/systemd/system/xpoliceclaw-site.service
sudo cp deploy/nginx/xpoliceclaw.conf.example /etc/nginx/sites-available/xpoliceclaw.conf
sudo ln -s /etc/nginx/sites-available/xpoliceclaw.conf /etc/nginx/sites-enabled/xpoliceclaw.conf
sudo systemctl daemon-reload
sudo systemctl enable --now xpoliceclaw-site
sudo nginx -t
sudo systemctl reload nginx
```

### Dynadot DNS

At Dynadot, open the domain management page for `xpoliceclaw.com`, switch to `Dynadot DNS`, then create:

- `A` record for `@` pointing to your VPS public IPv4 address
- optional `AAAA` record for `@` if your VPS has IPv6
- `CNAME` record for `www` pointing to `xpoliceclaw.com`

Dynadot DNS management reference:

- [Set DNS for your domain](https://www.dynadot.com/help/question/set-up-DNS)

### TLS

After DNS resolves to the VPS, issue HTTPS:

```bash
sudo apt-get update
sudo apt-get install -y certbot python3-certbot-nginx
sudo certbot --nginx -d xpoliceclaw.com -d www.xpoliceclaw.com
```

### What Visitors Will See

- `https://xpoliceclaw.com/`
  hosted download site mode
- `https://xpoliceclaw.com/download/windows/latest`
  direct Windows installer download
- `https://xpoliceclaw.com/architecture`
  architecture page

Remote visitors will not be able to call `/api/*`. Those routes remain local-only by design.

## Runtime Layout

By default, the project no longer writes runtime history and reports into the repository root.

On Windows, the runtime root is:

```text
%LocalAppData%\Xpoliceclaw
```

It contains:

- `data\scan_history.json`
- `data\uninstall_history.json`
- `reports\<scan-id>\Police_Claw_v3_Report.json`
- `reports\<scan-id>\Police_Claw_v3_Report.docx`
- `logs\`

You can override the runtime root with:

```powershell
$env:XPOLICECLAW_RUNTIME_ROOT = 'D:\Custom\PoliceClawRuntime'
```

The launcher and Flask entrypoint both respect this override.

The public download site can also override the installer directory with:

```powershell
$env:XPOLICECLAW_RELEASE_ROOT = 'D:\Custom\PoliceClawReleases'
```

## Local API Guardrails

The local API is no longer exposed as a bare loopback service.

- `/api/*` routes accept local requests only
- every API request requires a per-launch local client token
- the workbench injects that token into frontend requests automatically
- artifact download links include the same token in their generated URL

This does not replace a full desktop security model, but it blocks trivial cross-origin calls from unrelated local browser pages.

## Windows Packaging Notes

- `app_metadata.py` is the single source for product name, executable name, publisher, and version
- `client_launcher.spec` builds the Windows executable with file version metadata
- `tools\build_windows.ps1` builds the standalone desktop executable, with optional `-WithWebview` support
- `installer\PoliceClaw.iss` creates a per-user installer under `%LocalAppData%\Programs\Xpoliceclaw`
- `tools\build_release.ps1` is the release entrypoint for producing both the executable and the installer, with optional `-WithWebview` support
- the installer creates Start Menu and optional desktop shortcuts, and registers an uninstall entry

## Directory Layout

```text
Xpoliceclaw/
|- app_runtime.py
|- client_launcher.py
|- client_launcher.spec
|- web_app.py
|- scanner_service.py
|- uninstall_service.py
|- police_claw_v3.py
|- requirements.txt
|- requirements-desktop.txt
|- requirements-webview.txt
|- app_metadata.py
|- templates/
|  \- index.html
|- static/
|  |- app.js
|  \- styles.css
|- sample_data/
|  \- demo_fixture.json
|- installer/
|  \- PoliceClaw.iss
|- tools/
|  |- load_demo_data.py
|  |- build_windows.ps1
|  \- build_release.ps1
|- index.html
\- generate_architecture_site.py
```

## API Overview

### Scan API

- `GET /api/health`
- `GET /api/scans`
- `POST /api/scans`
- `GET /api/scans/<job_id>`
- `GET /api/scans/<job_id>/artifacts/json`
- `GET /api/scans/<job_id>/artifacts/docx`

### Uninstall API

- `GET /api/uninstall/targets`
- `POST /api/uninstall`
- `GET /api/uninstall/<uninstall_id>`
- `GET /api/uninstall/<uninstall_id>/result`
- `GET /api/uninstall/history`

### Error Format

API errors use a consistent JSON shape:

```json
{
  "ok": false,
  "error": "invalid_uninstall_request",
  "message": "Confirmation text must be exactly 'UNINSTALL CONFIRMED'."
}
```

Successful JSON responses include `ok: true`.

## Demo Data

For a safe walkthrough, the project includes a curated demo fixture. It does not trigger a live scan or a live uninstall. It seeds persisted history under the runtime root so the workbench can render handled states, residual review, and uninstall history.

Load it with:

```powershell
.\.venv\Scripts\python tools\load_demo_data.py
```

Optional:

```powershell
.\.venv\Scripts\python tools\load_demo_data.py --skip-uninstall-history
```

After loading demo data:

- the current record is explicitly marked as demo in the workbench
- scan history is restored from the runtime `data\scan_history.json`
- seeded uninstall history is restored from the runtime `data\uninstall_history.json`

## Safety Boundaries

This project does not attempt broad or unsafe cleanup.

- automatic uninstall is conservative by design
- `blocked`, `manual review`, and `partial` are normal outcomes, not system errors
- the remover does not delete root paths, home roots, browser profile trees, workspace roots, or other broad directories
- some targets can only be terminated or partially cleaned
- the Windows launcher may request administrator elevation so protected uninstall steps can run locally
- driver-level persistence, injected code, browser store extensions, mobile device control, and other advanced forms are outside the current automatic removal scope

## Capability Scope

Current automatic handling is aimed at clearly scoped user-level tools such as:

- local Python, Node, or CLI agents
- user-level startup entries
- user-level config and cache footprints
- explicit executable files whose paths pass strict safety checks

Current persistence detection focuses on:

- Windows `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- Windows Startup folder
- Windows user-level scheduled tasks when they clearly match the target
- macOS `~/Library/LaunchAgents`
- Linux `~/.config/systemd/user`
- Linux `~/.config/autostart`

## Known Limitations

- the underlying `police_claw_v3.py` engine is still broad and can produce noisy findings depending on the host
- history persistence restores recent terminal summaries, not live task continuation
- automatic cleanup remains intentionally narrower than detection
- target inference is best-effort and can still produce blocked targets when evidence is too broad or overlaps protected user data
- the current Windows client skeleton now includes local UAC elevation, loopback API token checks, and an Inno Setup installer path, but it still does not include MSI packaging or self-update
- native `pywebview` bundling can still be environment-sensitive on Windows and may require extra local runtime dependencies

## Short Roadmap

- tighten noisy scan heuristics in `police_claw_v3.py`
- improve target inference precision for mixed toolchains
- add Windows-specific installation and elevation flow without widening delete boundaries
