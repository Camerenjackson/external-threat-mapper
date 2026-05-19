# External Threat Mapper

<p align="center">
  <img src="docs/screenshots/app-icon.png" alt="External Threat Mapper" width="120"/>
</p>

<p align="center">
  <strong>Defensive external attack surface dashboard</strong><br/>
  PowerShell + WPF · optional API enrichment · local history + SQL sync
</p>

> **Authorized assessments only.** Use on targets you own or are permitted to test.

**Repository (private):** [github.com/Camerenjackson/external-threat-mapper](https://github.com/Camerenjackson/external-threat-mapper)

## Features

- Modern sidebar UI (Dashboard, Target, Discovery, Threat Intel, Integrations, History, Reports)
- Passive / safe scan modes
- API integrations: Shodan, VirusTotal, SecurityTrails, Censys, urlscan.io, AbuseIPDB, GreyNoise, OTX, GitHub, HIBP
- **Where to find API key** hints under each integration
- Auto-saved scan history in `data/history/`
- Optional **SQL Server** sync
- GUI + command-line modes
- Windows `.exe` build via PyInstaller

## Quick start

| Action | Command |
|--------|---------|
| **GUI** | Double-click `Launch-ETM.cmd` |
| **GUI (PowerShell)** | `powershell -File .\Start-ExternalThreatMapper.ps1` |
| **CLI scan** | `powershell -File .\Start-ExternalThreatMapper.ps1 -Domain example.com` |
| **Test APIs** | `powershell -File .\Start-ExternalThreatMapper.ps1 -TestApis` |

See [GETTING-STARTED.md](GETTING-STARTED.md) for a plain-language walkthrough.

## Requirements

- Windows 10/11
- PowerShell 5.1+ (7 recommended)
- For `.exe` build: Python 3.10+

## Project layout

```
ExternalThreatMapper/
├── Launch-ETM.cmd          # Double-click launcher
├── Start-ExternalThreatMapper.ps1
├── assets/etm-icon.png     # App icon
├── UI/                     # WPF interface
├── Modules/                # Scan + API logic
├── data/history/           # Saved scans (local)
└── config/integrations.json
```

## Security

See [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
