# API integration map

How External Threat Mapper uses each provider during a scan. Only providers with saved keys run.

## Scan pipeline order

1. **Passive discovery** — Certificate Transparency (`crt.sh`) + optional DNS prefix checks  
2. **API discovery** — Shodan DNS + SecurityTrails subdomains → merged into asset list  
3. **Typosquat / cloud / GitHub** — passive checks per scan mode  
4. **Threat intel (domain)** — reputation and exposure on the primary domain  
5. **Threat intel (cascade)** — IPs and hostnames from steps 1–4 fed into VT, Shodan host, AbuseIPDB, GreyNoise, OTX  
6. **HIBP** — organizational breach aliases (`breachedDomain`) + optional seed emails  
7. **Web probe** — safe HTTP checks on top hostnames  
8. **Threat intel (follow-up)** — VirusTotal (+ cascade) on hosts seen by web probe  

Configure rate limits in `config/config.json` → `threatIntel` (`maxIpLookups`, `apiDelayMs`, etc.).

## Provider reference

| Provider | Official docs | What ETM calls | Purpose |
|----------|---------------|----------------|---------|
| **Shodan** | https://developer.shodan.io/api | `dns/domain`, `shodan/host/{ip}` | Find subdomains in the wild; ports/services/vulns on discovered IPs |
| **VirusTotal** | https://developers.virustotal.com/reference/overview | `domains/{id}`, `ip_addresses/{id}` | Domain + per-IP + per-hostname reputation |
| **SecurityTrails** | https://docs.securitytrails.com/docs | `domain/{d}`, `domain/{d}/subdomains` | Historical DNS; subdomain inventory |
| **Censys** | https://search.censys.io/api | `v2/hosts/search` | Hosts/certificates mentioning the domain; sample IPs |
| **urlscan.io** | https://urlscan.io/docs/api/ | `search/?q=domain:` | Phishing/historical URL captures |
| **AbuseIPDB** | https://docs.abuseipdb.com/ | `check` | Abuse score for each discovered IP |
| **GreyNoise** | https://docs.greynoise.io/docs/ | `v3/ip/{ip}` (then community fallback) | Scanner/noise vs benign (RIOT) |
| **AlienVault OTX** | https://otx.alienvault.com/api | `indicators/domain`, `indicators/IPv4` | Threat pulses on domain and IPs |
| **GitHub** | https://docs.github.com/en/rest/search | `search/code` | Public code referencing the domain |
| **HIBP** | https://haveibeenpwned.com/API/v3 | `breacheddomain`, `stealerLogsByEmailDomain`, optional `breachedaccount` | Corp mailbox breach exposure (domain must be verified in HIBP dashboard) |

## Design choices

- **Corporate-first** — Domain and subdomain discovery drive the scan; APIs enrich what was found, not random single-email lookups.  
- **Cascade** — A discovered IP triggers every configured IP-capable API (up to `maxIpLookups`).  
- **Dedup** — Intel rows are deduplicated by provider + asset + summary to avoid duplicate grid noise.  
- **Passive** — No exploitation; Shodan host lookup reads public index data only.  
- **HIBP separate** — Breach data is not mixed into generic threat-intel to keep licensing/verification messaging clear.  

## Keys and testing

Use **Integrations** → **Test** per provider, or **Test all connections**.  
HIBP test uses `subscribedDomains` and reports verified domains on your subscription.
