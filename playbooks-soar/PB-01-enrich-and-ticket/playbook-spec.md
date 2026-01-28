# PB-01 — Enrich Incident & Create Ticket (Safe, Automatic)

## Objective
When a **new Microsoft Sentinel incident** is created (especially identity-focused alerts), automatically:
1) Extract key entities (Account/IP) from the incident
2) Run a small set of KQL enrichment queries
3) Add a structured evidence comment back to the incident
4) Create a ticket (GitHub-based, or any ITSM later) and link it

This playbook is **safe by design**: enrichment + documentation + routing only.

## Trigger (recommended)
**Microsoft Sentinel incident** trigger (incident created / updated).  
Microsoft documents this trigger as recommended for most incident automation scenarios and notes the incident object includes alerts and entities. :contentReference[oaicite:5]{index=5}

## Required inputs (from trigger dynamic content)
- Incident ARM ID (for comment/update actions)
- Incident title, severity, status
- Entities array (Accounts, IPs)
- Alerts array

## Core steps (Logic App workflow outline)
### 1) Filter: run only for identity incidents
Condition examples:
- Incident title contains `DET-0` (DET-01..07)
- OR incident contains an Account/IP entity
- OR incident product name indicates Entra / identity (if available)

### 2) Extract entities
Preferred approach:
- Use Sentinel “Entities” actions to extract Accounts and IPs (native entity types). :contentReference[oaicite:6]{index=6}  
If needed, parse/loop the `Entities` array into:
- `accounts[]` (UPNs)
- `ips[]`

### 3) Enrichment queries (Azure Monitor Logs)
Run a few targeted KQL queries against the workspace (fast and high-signal):
- Recent sign-ins for the main account (last 24h)
- Sign-ins from the suspicious IP (last 24h)
- Recent AuditLogs for the account (role/consent/cred/MFA changes)

(We keep the query set small and aggregated—SOC-friendly and cost-conscious.)

### 4) Build an “Investigation Bundle” object
Create a JSON object with:
- Incident metadata
- Accounts/IPs extracted
- KQL enrichment results
- Suggested next steps (based on which DETs match)

### 5) Add comment to the Sentinel incident (audit trail)
Use **Add comment to incident (V3)** to post a formatted comment including:
- What triggered this playbook
- Key entities
- Enrichment highlights
- Link to ticket

Microsoft documents Add comment to incident (V3) and notes actions require the Incident ARM ID. :contentReference[oaicite:7]{index=7}

### 6) Create ticket (zero-cost friendly option)
Preferred “free portfolio” option:
- Trigger a GitHub workflow via **repository_dispatch** (GitHub connector supports dispatch events). :contentReference[oaicite:8]{index=8}  
Then GitHub Actions creates/updates an Issue inside your repo (so the ticket is visible to recruiters).

Alternative later:
- Jira/ServiceNow/Teams/email connectors (enterprise)
- Same playbook logic; only the “ticket action” changes.

## Output
- A well-structured comment in the Sentinel incident
- A ticket containing the incident summary and evidence pointers
- (Optional) notification message

## Permissions (production-minded)
- Use Managed Identity for Sentinel connector where possible (common Sentinel playbook pattern). :contentReference[oaicite:9]{index=9}
- Ensure playbook identity has rights required to comment/update incidents (Responder/Contributor is commonly needed for write operations). :contentReference[oaicite:10]{index=10}

## Testing plan (offline-first)
- Use the local harness output (`alerts.json` later) to generate a “mock incident” payload
- Validate:
  - entity extraction logic
  - comment formatting template
  - ticket formatting template
