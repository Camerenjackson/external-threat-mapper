#!/usr/bin/env python3
"""Launch External Threat Mapper WPF GUI (Windows). Finds PowerShell and uses STA thread."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


def get_app_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS)  # type: ignore[attr-defined]
    return Path(__file__).resolve().parent.parent


ROOT = get_app_root()
START_SCRIPT = ROOT / "Start-ExternalThreatMapper.ps1"
CONFIG_DIR = ROOT / "config"
EXAMPLE_CONFIG = CONFIG_DIR / "config.example.json"
USER_CONFIG = CONFIG_DIR / "config.json"


def find_powershell() -> list[str]:
    candidates: list[str] = []
    for name in ("pwsh", "pwsh.exe", "powershell", "powershell.exe"):
        path = shutil.which(name)
        if path and path not in candidates:
            candidates.append(path)
    for path in (
        r"C:\Program Files\PowerShell\7\pwsh.exe",
        r"C:\Program Files (x86)\PowerShell\7\pwsh.exe",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    ):
        if os.path.isfile(path) and path not in candidates:
            candidates.append(path)
    return candidates


def ensure_config() -> None:
    if not USER_CONFIG.exists() and EXAMPLE_CONFIG.exists():
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        USER_CONFIG.write_text(EXAMPLE_CONFIG.read_text(encoding="utf-8"), encoding="utf-8")


def main() -> int:
    if sys.platform != "win32":
        print("The WPF GUI runs on Windows only.")
        print("For Linux/macOS use Docker: docker compose up")
        return 1

    # Pass through CLI args to PowerShell (e.g. -Domain, -TestApis)
    extra = sys.argv[1:]

    if not START_SCRIPT.is_file():
        print(f"Missing launcher script: {START_SCRIPT}")
        return 1

    ensure_config()

    shells = find_powershell()
    if not shells:
        print("PowerShell not found. Install PowerShell 7:")
        print("  winget install Microsoft.PowerShell")
        return 1

    os.environ["ETM_APP_ROOT"] = str(ROOT)

    exe = shells[0]
    use_sta = not extra  # GUI only when no CLI flags
    cmd = [
        exe,
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
    ]
    if use_sta:
        cmd.append("-STA")
    cmd.extend(["-File", str(START_SCRIPT)])
    cmd.extend(extra)
    try:
        return subprocess.call(cmd, cwd=str(ROOT))
    except KeyboardInterrupt:
        return 130
    except OSError as exc:
        print(f"Failed to start: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
