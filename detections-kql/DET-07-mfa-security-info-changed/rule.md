# DET-07 — MFA Method / Security Info Changed

## Purpose
Detects changes to MFA methods or authentication/security info (e.g., adding/removing phone, Authenticator, FIDO, changing default method).
This is a high-signal indicator after credential compromise because attackers often modify security info to lock in access.

## Data Sources
- `AuditLogs` (Microsoft Entra ID audit logs)

## Severity (recommended)
High for privileged/VIP users; Medium for standard users (raise severity if paired with suspicious sign-in patterns).

## KQL
- Primary: `query.kql` (broad/resilient across tenants)
- Alternative: `query-alternative.kql` (operation-name focused)

## How it works (logic)
1. Search audit events in the lookback window.
2. Filter for authentication/security-info related operations.
3. Expand `TargetResources` to capture the affected user and method details.
4. Output initiator + raw payload for investigation.

## Tunable parameters
- `lookback` (default `14d`)
- `includeFailed` (primary query)

## Tuning guidance
- Raise severity when:
  - target user is privileged/VIP
  - initiator is not the same as the target user (admin/automation vs self-service)
  - change occurs soon after DET-01/DET-03 activity
- Reduce noise by excluding approved helpdesk/admin automation accounts.

## Common false positives
- Legit user phone/device change.
- Helpdesk assisting with MFA reset during onboarding.
- Planned security info re-registration campaigns.

## Investigation steps (suggested)
- Confirm whether the user initiated the change or an admin did.
- Check the user’s sign-in activity around the change (unusual IP, new country, failure bursts).
- If suspicious: reset credentials, revoke sessions, require re-registration of MFA, and review role/group changes.

## Validation approach (this repo)
- Offline mode: sample AuditLogs can include a security info update event (optional enhancement).
- Cloud mode: validate by adding/removing a test authentication method for a test user in a controlled tenant.

## MITRE ATT&CK mapping
- **T1098** — Account Manipulation
- **T1556** — Modify Authentication Process
