# Police Claw Workbench

Police Claw, also called `Xpoliceclaw`, is a local security scan and response workbench built around the existing `police_claw_v3.py` engine.

It packages the scanner into a Flask-based website that can:

- run real local scans in the background
- present scan output in a report workbench
- export structured JSON and DOCX reports
- infer removable targets from the latest completed scan
- execute conservative uninstall tasks as background jobs
- persist recent scan and uninstall history across restarts

The project is intentionally conservative. It is designed to explain, contain, and clean up clearly scoped user-level footprints, not to behave like an unrestricted remover.

## Architecture

The current project stays within the existing stack:

- `web_app.py`
  Thin Flask entrypoint and API layer
- `scanner_service.py`
  Background scan orchestration, report persistence, scan history loading, and demo fixture import
- `uninstall_service.py`
  Target inference, uninstall task state machine, persistence cleanup, path safety checks, and uninstall history persistence
- `police_claw_v3.py`
  Original single-file scan engine and report writer
- `templates/index.html`
  Server-rendered workbench shell
- `static/app.js`
  Polling, state management, rendering, error handling, and uninstall workflow
- `static/styles.css`
  Shared workbench styling

## Quick Start

### Requirements

- Windows, macOS, or Linux
- Python `3.11+`
- A local environment where `psutil` can inspect basic system state

### Install

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install --upgrade pip
.\.venv\Scripts\python -m pip install -r requirements.txt
```

### Run

```powershell
.\.venv\Scripts\python web_app.py
```

Default address:

- [http://127.0.0.1:5000](http://127.0.0.1:5000)

The first run automatically prepares these runtime directories if they do not exist:

- `reports/`
- `data/`

## Directory Layout

```text
Xpoliceclaw/
|- web_app.py
|- scanner_service.py
|- uninstall_service.py
|- police_claw_v3.py
|- templates/
|  \- index.html
|- static/
|  |- app.js
|  \- styles.css
|- reports/                  # generated report artifacts, one folder per scan
|- data/                     # persisted scan_history.json and uninstall_history.json
|- sample_data/
|  \- demo_fixture.json      # curated demo fixture
|- tools/
|  \- load_demo_data.py      # loads demo fixture into persisted history
|- index.html                # architecture page
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

API errors are returned as JSON and use the same shape across scan and uninstall routes:

```json
{
  "ok": false,
  "error": "invalid_uninstall_request",
  "message": "Confirmation text must be exactly 'UNINSTALL CONFIRMED'."
}
```

Successful JSON responses include `ok: true`.

## Runtime Output

### `reports/`

Each completed scan writes its artifacts under a scan-specific folder:

- `Police_Claw_v3_Report.json`
- `Police_Claw_v3_Report.docx`

### `data/`

The workbench persists recent terminal history here:

- `scan_history.json`
- `uninstall_history.json`

Only recent completed or terminal records are restored. In-progress tasks are not resumed after restart.

## Safety Boundaries

This project does not attempt broad or unsafe cleanup.

- Automatic uninstall is conservative by design.
- `blocked`, `manual review`, and `partial` are normal outcomes, not system errors.
- The remover does not delete root paths, home roots, browser profile trees, workspace roots, or other broad directories.
- Some targets can only be terminated or partially cleaned.
- Driver-level persistence, injected code, browser store extensions, mobile device control, complex enterprise persistence, and other advanced forms are outside the current automatic removal scope.

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

## Demo Data

For safe demonstrations, the project includes a curated demo fixture. It does not trigger a real scan or a real uninstall. It seeds persisted history so the workbench can render a realistic report, handled states, and residual review flow.

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
- scan history is restored from `data/scan_history.json`
- seeded uninstall history is restored from `data/uninstall_history.json`

If you want a clean local state again, remove the generated contents under `data/` and `reports/`.

## Demo Suggestions

For a stable walkthrough:

1. Load the demo fixture.
2. Start the Flask app.
3. Open the workbench and review the Executive Summary, Findings, and Residual Review panels.
4. Show the persisted scan and uninstall history after a restart.
5. Optionally run one live scan afterward to contrast demo data with a real background job.

## Known Limitations

- The underlying `police_claw_v3.py` engine is still a broad scanner and can produce noisy findings depending on the host.
- History persistence restores recent terminal summaries, not live task continuation.
- Automatic cleanup remains intentionally narrower than detection.
- Target inference is best-effort and can still produce blocked targets when evidence is too broad or overlaps protected user data.
- DOCX export depends on `python-docx` being available.

## Maintenance Notes

- `scanner_service.py` and `uninstall_service.py` own the runtime history format. Keep any future changes backward aware.
- The front end expects JSON API responses from `/api/...` routes and now handles non-JSON server failures more gracefully, but the API should remain JSON-first.
- Demo support should remain clearly labeled and separate from live scan behavior.

## Short Roadmap

- tighten noisy scan heuristics in `police_claw_v3.py`
- improve target inference precision for mixed toolchains
- expand safe persistence coverage without widening delete boundaries
