# DET-06 — OAuth Consent Granted to an Application

## Purpose
Detects when a user or admin grants OAuth permissions to an application/service principal.
OAuth consent abuse is a common technique for persistence and data access (e.g., mail/drive read).

## Data Sources
- `AuditLogs` (Microsoft Entra ID audit logs)

## Severity (recommended)
Medium → High depending on:
- permission scopes granted (high privilege = High)
- initiator account (privileged/VIP = High)
- app reputation / unexpected app registration

## KQL
- Primary: `query.kql` (broad and resilient across naming differences)
- Alternative: `query-alternative.kql` (tighter operation-name matching)

## How it works (logic)
1. Search audit events for consent/grant-like operations.
2. Extract initiator identity (user or app).
3. Expand `TargetResources` to identify which application/service principal is involved.
4. Keep events that look like permission/scope/consent changes.
5. Output key context and the raw audit payload for investigation.

## Tunable parameters
- `lookback` (default `30d`)
- `includeFailed` (in primary query)

## Tuning guidance
- Reduce noise by allowlisting known enterprise apps (Microsoft apps, approved vendors).
- Raise severity when:
  - consent includes high impact permissions (Mail.Read, Files.Read.All, Directory.Read.All, etc.)
  - consent is granted by a non-admin user to an unknown app
  - consent occurs shortly after DET-01 / DET-03 signals

## Common false positives
- Legit users onboarding approved apps that require consent.
- Admin granting consent for planned SaaS integrations.

## Investigation steps (suggested)
- Identify what permissions/scopes were granted (look inside `TargetResources.modifiedProperties`).
- Verify app legitimacy (publisher, redirect URIs, sign-in behavior).
- Check if the user recently had suspicious sign-ins (pair with DET-01/DET-03).
- If suspicious: revoke consent, disable the app/service principal, reset user credentials, review mailbox/file access.

## Validation approach (this repo)
- Offline dataset contains a sample audit event "Consent to application".
- Cloud mode: validate by granting consent to a test app in a controlled tenant.

## MITRE ATT&CK mapping
- **T1528** — Steal Application Access Token (often related to OAuth abuse flows)
- **T1098** — Account Manipulation (granting/reconfiguring access)
- **T1078** — Valid Accounts (compromised accounts granting consent)
