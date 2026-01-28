# DET-04 — Privileged Role Assignment / Role Membership Change

## Purpose
Detects changes that add users to **high-privilege Entra roles** (e.g., Global Administrator).
This is a critical alert because it can represent privilege escalation during account compromise.

## Data Sources
- `AuditLogs` (Microsoft Entra ID audit logs)

## Severity (recommended)
High

## KQL
See `query.kql`.

## How it works (logic)
1. Search audit events in the lookback window for role-related operations.
2. Parse initiator identity (`InitiatedBy.user.userPrincipalName`).
3. Expand `TargetResources` to view the role/user objects impacted.
4. Match operations/targets against a configurable list of privileged roles.
5. Output key context + full `TargetResources` for investigation.

## Tunable parameters
- `lookback` (default `7d`)
- `includeFailed` (default `false`)
- `privilegedRoleKeywords` (update to match your org’s high-value roles)

## Tuning guidance
- In mature tenants, consider splitting into two detections:
  - “Privileged role assignment success” (High)
  - “Privileged role assignment attempted/failed” (Medium)
- Reduce noise by allowlisting:
  - known admin automation accounts
  - planned change windows (change ticket correlation)
- Increase confidence when:
  - initiator is unusual for the environment
  - the target account is newly created
  - the same initiator makes multiple privileged changes in a short time

## Common false positives
- Legit admin onboarding/offboarding tasks.
- Planned role changes approved through ITSM.

## Investigation steps (suggested)
- Confirm initiator legitimacy (who/what performed the change).
- Check initiator’s sign-in history around the event.
- Verify whether the change matches an approved ticket.
- Review additional audit events near the same `CorrelationId`.

## Validation approach (this repo)
- Offline dataset includes a sample audit event that adds a user to "Global Administrator".
- In cloud mode, validate using a test admin account and a test role assignment (in a controlled tenant).

## MITRE ATT&CK mapping
- **T1098** — Account Manipulation
- **T1078** — Valid Accounts (often paired with privilege escalation)
