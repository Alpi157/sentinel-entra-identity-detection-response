# DET-05 — App / Service Principal Credentials Added (Secret/Key/Certificate)

## Purpose
Detects when credentials are added or updated on an Entra **Application** or **Service Principal**
(e.g., adding a client secret or certificate). This is a high-risk event and a common persistence method.

## Data Sources
- `AuditLogs` (Microsoft Entra ID audit logs)

## Severity (recommended)
High (especially if the initiator is unusual or the app is high-privilege)

## KQL
See `query.kql`.

## How it works (logic)
1. Search `AuditLogs` in the lookback window for operations indicating credential changes.
2. Expand `TargetResources` to identify which application/service principal was affected.
3. Keep events where:
   - Target type is Application/ServicePrincipal, or
   - modifiedProperties suggest a credential/secret/key/cert change.
4. Output initiator identity, target, and full `TargetResources` payload for investigation.

## Tunable parameters
- `lookback` (default `14d`)
- `includeFailed` (default `false`)
- `credOps` list (expand with tenant-specific operation names if needed)

## Tuning guidance
- Allowlist known app lifecycle automation accounts (CI/CD, IaC pipelines).
- Boost severity when:
  - initiator is a non-admin or rarely seen admin account
  - credential is added outside change windows
  - target app has high privileges (Graph permissions, directory roles, admin consent)
- Consider splitting into two rules:
  - “Credential added” (High)
  - “Credential updated/changed” (Medium)

## Common false positives
- Planned app secret rotation (DevOps).
- New app onboarding.

## Investigation steps (suggested)
- Confirm initiator legitimacy (user/app, device, sign-in history).
- Identify if this change matches a change ticket.
- Review app permissions (Graph scopes, admin consent status).
- Check for related events: consent grants, new service principal creation, unusual sign-ins.

## Validation approach (this repo)
- Offline dataset includes a sample audit event: "Add service principal credentials" on a test app.
- Cloud mode: validate in a controlled tenant by rotating a secret on a test app.

## MITRE ATT&CK mapping
- **T1098** — Account Manipulation (identity configuration changes)
- **T1550** — Use Alternate Authentication Material (credentials/certs/secrets used for access)
