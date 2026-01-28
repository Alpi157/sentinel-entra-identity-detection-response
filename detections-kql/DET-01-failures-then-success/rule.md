# Detection 01 — Multiple Failures Followed by Success (Same IP)

## Purpose
Detects a burst of failed Entra ID sign-ins from the same IP address followed by a successful sign-in soon after.
This pattern can indicate password spraying, credential stuffing, or repeated guesses that eventually succeed.

## Data Sources
- `SigninLogs` (Microsoft Entra ID sign-in logs)

## Severity (recommended)
High (raise to High when `FailedUsers` is high or when the successful user is privileged/VIP)

## KQL
See `query.kql`.

## How it works (logic)
1. Find failed sign-ins in the lookback window.
2. Summarize failures by IP:
   - failure count
   - distinct targeted users
   - time range of failures
3. Join with successful sign-ins from the same IP.
4. Alert when a success occurs within `successWindow` of the failure burst.

## Tunable parameters
- `lookback` (default `1d`)
- `failThreshold` (default `10`)
- `successWindow` (default `30m`)

## Tuning guidance
- Start with `failThreshold=10` in labs.
- In enterprise environments, tune by:
  - excluding known corporate NAT/VPN egress IPs (watchlist)
  - raising the threshold for IPs belonging to corporate networks
  - boosting severity when targeted users include admins/VIPs

## Common false positives
- Corporate VPN/NAT where many users mistype passwords and one succeeds.
- Password reset/rollout events causing bursts of failures.
- Misconfigured apps repeatedly retrying authentication.

## Validation approach (this repo)
- Sample dataset includes 15 failures from IP `203.0.113.77` followed by a success for `standard.user1@lab.local`.
- Local runner confirms the alert fires:
  - `tools/local-kql/run_detections.py`

## MITRE ATT&CK mapping
- **T1110** — Brute Force (Password Spraying / Credential Stuffing patterns)
