# Security & Authorized Use Policy

## Authorized use only

**External Threat Mapper** is a **defensive** external attack surface visibility tool. Use it only on:

- Domains, IP ranges, and brands you **own** or are **explicitly authorized** to assess
- Systems covered by a written scope of work, contract, or internal security program

Unauthorized scanning or reconnaissance may violate law and organizational policy.

## Defensive design principles

| Principle | Implementation |
|-----------|----------------|
| Passive by default | `PassiveOnly` scan mode is the default |
| No exploitation | No exploit modules, payload delivery, or auth bypass |
| No credential attacks | No password spraying, stuffing, or validation |
| No brute force | No directory busting at scale; rate limits enforced |
| Secret safety | GitHub findings redact suspected secrets; never validate tokens |
| API key safety | Keys stored via DPAPI; never logged or displayed in full |

## Corporate deployment

- Use **Corporate Safe** or **Passive Only** on production-adjacent assets unless active testing is approved
- Maintain scope files with exclusions
- Enable audit logging for accountability
- Restrict API keys to least-privilege tokens

## Reporting vulnerabilities

Report issues in this launcher via GitHub Security Advisories. For Caldera (if integrated separately), follow MITRE's disclosure process.
