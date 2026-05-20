# Getting started (simple guide)

## What this app does

External Threat Mapper helps you **see what attackers might find** about your organization on the internet (domains, subdomains, reputation APIs). It is for **authorized defensive** use only.

## Easiest way to open the app

1. Go to the project folder.
2. Double-click **`Launch-ETM.cmd`**.

## First-time setup (2 minutes)

1. Open the app and click **Yes** on the authorization prompt (required once; **No** closes the app).
2. Click **Integrations** and add any API keys you have (optional for demo).
3. Open **Target** and enter a domain you are allowed to test.
4. Check the authorization box.
5. Click **Demo** on the dashboard to load sample data, or **Run scan** for a real passive scan.

## Command line (no window)

Open PowerShell in the project folder:

```powershell
# Help
powershell -File .\Start-ExternalThreatMapper.ps1 -Help

# Load-style test without GUI (use a domain you own)
powershell -File .\Start-ExternalThreatMapper.ps1 -Domain example.com -ScanMode PassiveOnly

# Test API keys
powershell -File .\Start-ExternalThreatMapper.ps1 -TestApis
```

Reports save to the `reports\` folder. History saves to `data\history\`.

## Build the .exe

```powershell
.\build.ps1
```

Output: `dist\ExternalThreatMapper.exe`

## SQL (optional)

**SQL Database** tab → enter server and database → **Connect** → unlock sync tools.

**History** tab → local scans only (`data\history\`). Use **Load selected** to reopen a past scan.

## Verify install (no GUI)

```powershell
powershell -File .\Scripts\Test-ETMCore.ps1
```

## At home vs at work

| Situation | What to do |
|-----------|----------------|
| No API keys | **Run scan** still works (DNS, certificate transparency, typosquat checks). |
| Some keys | Add them under **Integrations**; missing providers are skipped. |
| SQL at work | **SQL Database** → **Connect** → enable auto-sync. |
| Demo / training | **Demo** loads sample data; **Clear** resets the dashboard. |
