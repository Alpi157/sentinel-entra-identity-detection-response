# DET-02 — Legacy Authentication Usage

## Purpose
Detects sign-ins using **legacy authentication clients** (e.g., IMAP/POP/SMTP/MAPI/EAS/“Other clients”).
Legacy auth is commonly targeted because it may bypass modern controls like MFA and Conditional Access policies in less mature environments.

## Data Sources
- `SigninLogs` (Microsoft Entra ID sign-in logs)

## Severity (recommended)
Medium → High if the user is privileged/VIP or if the IP/location is unusual.

## KQL
See `query.kql`.

## How it works (logic)
1. Filter to sign-ins in the lookback window.
2. Match events where `ClientAppUsed` indicates legacy/other clients.
3. Optionally alert only on successful sign-ins (higher signal).

## Tunable parameters
- `lookback` (default `1d`)
- `includeSuccessOnly` (default `true`)

## Tuning guidance
- Exclude known approved legacy apps (if you must support them) by:
  - allowlisting specific `AppDisplayName` values
  - allowlisting known service accounts
- Escalate severity when:
  - user is in a privileged/VIP watchlist
  - IP is not in known corporate egress ranges

## Common false positives
- Legit legacy mail clients (older Outlook/mobile devices) in environments that still permit them.
- Service accounts configured for SMTP relay (should be documented/approved).

## Validation approach (this repo)
- Sample dataset includes a successful legacy auth sign-in event.
- Local runner will output DET-02 evidence from `tools/local-kql/run_detections.py`.

## MITRE ATT&CK mapping
Legacy auth itself is not a technique, but it is strongly associated with:
- **T1078** — Valid Accounts (abuse of valid creds)
