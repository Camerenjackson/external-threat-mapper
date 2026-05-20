# Project structure

The repository root stays small: launchers, module entry, and docs. Runtime scripts and build tooling live under `Scripts/`.

```
ExternalThreatMapper/
├── Launch-ETM.cmd / Launch-ETM.vbs   # Windows shortcuts (root)
├── ExternalThreatMapper.psm1         # Imports all Modules/
├── docker-compose.yml
├── README.md, GETTING-STARTED.md, SECURITY.md, LICENSE
│
├── Scripts/
│   ├── Start-ExternalThreatMapper.ps1   # GUI + CLI entry
│   ├── Start-ETMHttpService.ps1         # Docker HTTP API
│   ├── build.ps1                        # PyInstaller build
│   ├── requirements-build.txt
│   └── Test-ETMCore.ps1                 # Smoke test
│
├── launcher/
│   ├── launch_gui.py                    # Used by Launch-ETM.cmd (Python path)
│   └── main.py                          # PyInstaller entry point
│
├── Modules/          # PowerShell modules (scan, APIs, history, SQL)
├── UI/               # WPF (MainWindow.xaml / .ps1)
├── config/           # config.example.json, integrations.json
├── data/             # Local store + history (gitignored payloads)
├── docker/           # Dockerfile, entrypoint.ps1, .env.example
├── assets/           # App icon
├── docs/             # Guides and screenshots
├── samples/          # Demo JSON
└── scopes/           # Active scope file (gitignored except example)
```

## Path resolution

- **`Get-ETMProjectRoot`** (in `Modules/ConfigManager.psm1`) returns the folder that contains `Modules/`, `UI/`, and `ExternalThreatMapper.psm1`.
- **`ETM_APP_ROOT`** is set by the Python launcher and by `Scripts/Start-ExternalThreatMapper.ps1` so paths work when the start script is not run from the repo root.
- **Docker** uses `/app` as root; compose loads API keys from `docker/.env` (copy from `docker/.env.example`).

## Build output

`Scripts/build.ps1` writes `dist/ExternalThreatMapper.exe` at the project root (`dist/` is gitignored).
