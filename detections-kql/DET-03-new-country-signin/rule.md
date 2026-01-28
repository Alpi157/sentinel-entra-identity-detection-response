# DET-03 — New Country Sign-in (Baseline vs Recent)

## Purpose
Detects successful sign-ins from a country/region the user has not used during the baseline period.
This can indicate compromised credentials being used from an attacker’s infrastructure or unexpected travel.

## Data Sources
- `SigninLogs` (Microsoft Entra ID sign-in logs)

## Severity (recommended)
Medium (raise to High for privileged/VIP users or when paired with other signals like failure bursts, risky user agents, or suspicious OAuth consent).

## KQL
See `query.kql`.

## How it works (logic)
1. Build a per-user baseline of known countries from a historical window (`baselineWindow`), excluding the most recent period (`recentWindow`).
2. Summarize recent successful sign-ins by user + country.
3. Alert when the recent country is NOT in the baseline set and the event repeats at least `minNewCountryHits`.

## Tunable parameters
- `baselineWindow` (default `14d`)
- `recentWindow` (default `1d`)
- `minNewCountryHits` (default `2`)

## Tuning guidance
- If your environment has frequent travel, increase `minNewCountryHits` or add allowlists for known travel scenarios.
- Consider excluding known corporate VPN exit countries (e.g., if users always appear from a US VPN).
- Escalate severity when:
  - user is privileged/VIP
  - the same IP targets multiple users (pair with DET-01)
  - the sign-in uses legacy auth (pair with DET-02)

## Common false positives
- Legitimate travel.
- New VPN exit nodes (corporate VPN changes).
- Cellular carriers routing traffic through neighboring countries.

## Validation approach (this repo)
- In the cloud deployment mode, validate by signing in from two different locations (or using controlled test IPs).
- In offline mode, sample data can include a non-baseline country event to ensure the query is exercised.

## MITRE ATT&CK mapping
This is an anomaly indicator typically associated with credential compromise:
- **T1078** — Valid Accounts
