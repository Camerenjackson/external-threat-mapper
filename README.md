# External Threat Mapper

<p align="center">
  <img src="docs/screenshots/social-preview.png" alt="External Threat Mapper dashboard preview" width="720"/>
</p>

<p align="center">
  <a href="https://github.com/Camerenjackson/external-threat-mapper/blob/master/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"/></a>
  <img src="https://img.shields.io/badge/platform-Windows-0078D6?logo=windows" alt="Windows"/>
  <img src="https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white" alt="PowerShell"/>
  <img src="https://img.shields.io/badge/UI-WPF-512BD4" alt="WPF"/>
</p>

<p align="center">
  <strong>Defensive external attack surface dashboard</strong><br/>
  PowerShell + WPF · optional API enrichment · local history + SQL sync
</p>

> **Authorized assessments only.** Use on targets you own or are permitted to test.

**Repository:** [github.com/Camerenjackson/external-threat-mapper](https://github.com/Camerenjackson/external-threat-mapper)

## Features

- Modern sidebar UI (Dashboard, Target, Discovery, Threat Intel, Integrations, History, Reports)
- Passive / safe scan modes
- API integrations: Shodan, VirusTotal, SecurityTrails, Censys, urlscan.io, AbuseIPDB, GreyNoise, OTX, GitHub, HIBP
- **Where to find API key** hints under each integration
- API-assisted subdomain discovery (Shodan DNS + SecurityTrails) and IP cascade enrichment
- HIBP organizational breach exposure (verified domains + optional seed emails)
- Auto-saved scan history in `data/history/`
- Optional **SQL Server** sync
- GUI + command-line modes
- Windows `.exe` build via PyInstaller
- Docker headless scan + HTTP API (optional)

## Quick start

| Action | Command |
|--------|---------|
| **GUI** | Double-click `Launch-ETM.cmd` |
| **GUI (PowerShell)** | `powershell -STA -File .\Scripts\Start-ExternalThreatMapper.ps1` |
| **CLI scan** | `powershell -File .\Scripts\Start-ExternalThreatMapper.ps1 -Domain example.com` |
| **Test APIs** | `powershell -File .\Scripts\Start-ExternalThreatMapper.ps1 -TestApis` |

See [GETTING-STARTED.md](GETTING-STARTED.md) for a plain-language walkthrough.

## API keys (never committed)

Keys are stored locally only:

- **GUI:** Integrations tab (DPAPI-protected under `credentials/`)
- **Environment:** `ETM_*` variables (see `config/integrations.json`)
- **Docker:** copy `docker/.env.example` → `docker/.env`

Copy `config/config.example.json` → `config/config.json` for scan settings. These paths are in `.gitignore`.

## Requirements

- Windows 10/11
- PowerShell 5.1+ (7 recommended)
- For `.exe` build: Python 3.10+

## Project layout

```
ExternalThreatMapper/
├── Launch-ETM.cmd              # Double-click launcher
├── ExternalThreatMapper.psm1   # Module entry
├── Scripts/                    # Start script, build, tests
├── launcher/                   # Python GUI launcher + PyInstaller entry
├── UI/                         # WPF interface
├── Modules/                    # Scan + API logic
├── docker/                     # Dockerfile, .env.example
├── data/history/               # Saved scans (local, gitignored)
└── config/                     # App + integrations config
```

See [docs/PROJECT-STRUCTURE.md](docs/PROJECT-STRUCTURE.md) and [docs/API-INTEGRATIONS.md](docs/API-INTEGRATIONS.md).

## Security

See [SECURITY.md](SECURITY.md). Do not commit `config/config.json`, `credentials/`, `scopes/current-scope.json`, or scan output under `data/` or `reports/`.

## License

MIT — see [LICENSE](LICENSE).
