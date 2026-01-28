# SOC Runbook - Identity Threat Detection & Response (Sentinel + Entra)

## Purpose
This runbook describes the **standard operating procedure** for triaging and investigating identity-related alerts using:
- Sentinel/Entra tables: `SigninLogs`, `AuditLogs`
- Workbook: **Identity Investigations (Entra + Sentinel)** (`/workbooks/identity-investigations/`)
- Detections: **DET-01 → DET-07** (`/detections-kql/`)
- Enrichment tool + SOAR playbooks:
  - Graph investigation bundle (Python)
  - Logic Apps enrichment + ticket notification
  - Manual containment only (human approved)

**Principle:** Fast triage + consistent evidence collection + safe response actions.

---

## Scope
Covers identity threats and suspicious changes including:
- Failed sign-in bursts followed by success (credential guessing/spray pattern)
- Legacy authentication usage
- New-country sign-ins (baseline vs recent)
- Privileged role assignment changes
- App/service principal credential additions (secret/cert/key)
- OAuth consent grants
- MFA/security info changes

---

## Inputs and tools

### Inputs 
- Sentinel incident/alert (or offline demo alert output)
- Entities: user UPN, IP address, time window, app name, country/region
- Any associated audit event correlation IDs

### Tools 
- **Workbook**: `/workbooks/identity-investigations/`
- **Detections**: `/detections-kql/DET-*/`
- **(Later) Enrichment**: `/enrichment-graph/` (investigation bundle JSON)
- **(Later) SOAR**: `/playbooks-soar/` (enrichment + ticket; containment is manual trigger)

---

## Severity and priority model (simple + practical)

### High priority triggers 
- Privileged role assignments (DET-04)
- App credential added (DET-05) on high-impact apps
- MFA/security info changed (DET-07) for admins/VIPs
- Failure burst + success (DET-01), especially when multiple users are targeted or success occurs from unusual region

### Medium priority triggers
- Legacy auth usage (DET-02)
- OAuth consent grants (DET-06) when app is unknown or scopes are broad
- New-country sign-ins (DET-03) without other signals

### Low priority (informational)
- Single-country change with clear travel context
- Approved change tickets / known admin automation accounts

---

## Standard triage procedure (10–15 minutes)

### Step 1 — Validate alert integrity (2 minutes)
1) Confirm **time window** and **entities** (UPN, IP, app).
2) Confirm the event exists in logs (SigninLogs or AuditLogs).
3) Check for duplicate alerts (same IP/user in same window).

**Decision:** If the alert is clearly a duplicate of an already-open incident, attach evidence and merge/close as duplicate.

---

### Step 2 — Quick context in workbook (3–5 minutes)
Open the workbook: **Identity Investigations (Entra + Sentinel)**

1) Set `TimeRange` to match the alert window (start with Last 24h).
2) Look at:
   - KPI tiles
   - Sign-in success/failure trend
   - Top offending IPs and failing users
   - Country distribution

**Decision:** Determine whether this is isolated (one user) or systemic (many users / many IPs / widespread failures).

---

### Step 3 — Choose investigation path (User-first vs IP-first)
Use the alert context to pick a pivot:

**User-first** if:
- one user shows suspicious behavior (new country, MFA changes, consent grant)

**IP-first** if:
- one IP targets multiple users, or DET-01 triggers

---

## Investigation playbooks by detection

### DET-01 — Multiple failures followed by success (same IP)
**Goal:** determine if this is credential attack + confirmed compromise.

Steps:
1) In workbook DET-01 panel, record:
   - IP, failure count, time range, success user(s)
2) Pivot to **User timeline** for the success user:
   - did sign-in location change?
   - is it new country?
   - any legacy auth?
3) Pivot to IP context:
   - how many unique users did this IP target?
4) Check AuditLogs near the time:
   - role assignment (DET-04)
   - consent grant (DET-06)
   - app credentials added (DET-05)
   - MFA changes (DET-07)

Escalate to **High** if:
- success occurred from unusual region / unknown IP
- multiple users targeted
- followed by any DET-04/05/06/07 changes

---

### DET-02 — Legacy authentication usage
**Goal:** determine if legacy auth is expected/approved.

Steps:
1) Validate the event is successful.
2) Identify the account type:
   - user vs service account pattern
3) Check historical occurrences:
   - frequent and expected vs first-time
4) If first-time legacy auth:
   - pivot to User timeline and look for unusual IP/country
   - check for follow-on audit events

Recommended action:
- If not approved: recommend blocking legacy auth and rotating credentials (policy change may be out-of-scope in a lab).

---

### DET-03 — New country sign-in (baseline vs recent)
**Goal:** distinguish travel from compromise.

Steps:
1) Confirm baseline countries vs new country.
2) Verify if new country repeats (reduces false positives).
3) Check supporting signals:
   - failure burst (DET-01)
   - legacy auth (DET-02)
   - risky audit events (DET-04/05/06/07)
4) Ask for business context (in real environment):
   - travel, remote work, VPN changes

Escalate if:
- new country + suspicious IP + audit changes (especially consent or MFA changes)

---

### DET-04 — Privileged role assignment / membership change
**Goal:** treat as critical change-control event.

Steps:
1) Identify initiator (`InitiatedBy`) and target role/user.
2) Confirm if initiator is expected (approved admin vs unusual).
3) Check if there is an approved change ticket (in real org).
4) Pivot:
   - initiator’s sign-ins around change time
   - target user’s sign-ins
5) Check for clustering:
   - multiple privileged changes by same initiator in short time

Immediate actions (human approved):
- contain if unauthorized (disable initiator, remove role assignment)
- review other changes in same correlation window

---

### DET-05 — App / service principal credentials added
**Goal:** detect persistence via secrets/certs.

Steps:
1) Identify initiator and target application/service principal.
2) Review modifiedProperties for credential indicators.
3) Determine app criticality:
   - high-permission Graph scopes?
   - admin consent status?
4) Correlate with:
   - consent grants (DET-06)
   - role changes (DET-04)
   - suspicious sign-ins (DET-01/DET-03)

Immediate actions (human approved):
- remove suspicious credentials
- disable service principal if malicious
- rotate secrets and review app permissions

---

### DET-06 — OAuth consent granted
**Goal:** detect OAuth persistence and data access.

Steps:
1) Identify app/service principal and initiator (user/admin).
2) Inspect granted scopes/permissions in TargetResources.
3) Determine legitimacy:
   - known publisher/vendor?
   - expected business app?
4) Correlate with:
   - new app registration (if present)
   - app credential changes (DET-05)
   - suspicious sign-ins (DET-01/DET-03)

Immediate actions (human approved):
- revoke consent
- disable app/service principal if malicious
- reset user credentials and revoke sessions if compromise suspected

---

### DET-07 — MFA method / security info changed
**Goal:** treat as high-risk indicator of takeover stabilization.

Steps:
1) Identify target user and initiator (self-service vs admin).
2) Check if the change is expected (helpdesk ticket / onboarding).
3) Pivot to sign-in history before/after change:
   - new IP/country?
   - failure burst?
4) Check for additional changes:
   - role assignment, consent, app credentials

Immediate actions (human approved):
- require re-registration of MFA
- reset password, revoke sessions
- verify device/auth method ownership

---

## Evidence checklist (what to capture in every incident)
Capture and attach the following:

### Identity context
- User UPN + user type (standard / admin / VIP)
- IP address + country/region
- AppDisplayName + ClientAppUsed
- Time window (first seen, last seen)

### Sign-in evidence
- # failures, # successes
- notable error codes and conditional access status
- whether legacy auth was used
- whether country is new vs baseline

### Audit evidence
- role assignment events (who assigned what to whom)
- consent grants (app name, scopes if available)
- app credential changes (what changed, who did it)
- MFA/security info changes (what changed, who initiated)

### Decision + rationale
- Why escalated / contained / closed
- What additional mitigations are recommended

---

## Response actions (safe + production-minded)

### Allowed automated actions (low risk)
- Create a ticket/issue with evidence links
- Notify SOC channel (Teams/Email) with summary
- Enrichment: fetch user/app context via Graph and attach bundle

### Manual-only actions (human approval)
- Disable user sign-in
- Reset password / revoke sessions
- Remove role assignment
- Disable service principal
- Revoke OAuth consent
- Force MFA re-registration

**Rule:** containment actions must always be manual-triggered and documented.

---

## Closure criteria
Close as **True Positive** if:
- confirmed compromise, unauthorized changes, or repeated malicious patterns

Close as **False Positive** if:
- legitimate travel, known VPN shift, approved change ticket, verified onboarding

Close as **Benign** if:
- expected admin automation / known maintenance actions and no other signals

Every closure must include:
- evidence summary
- tuning recommendation (if any)

---

## Tuning and continuous improvement
For each detection that generates noise:
1) Document what caused the false positives
2) Add tuning notes to the detection `rule.md`:
   - thresholds
   - allowlists (known IPs, approved apps, admin accounts)
3) Update workbook pivots to surface allowlisted vs non-allowlisted results
4) Record changes in a tuning log (optional: `/docs/tuning-log.md`)

---

## Offline-first note 
This repository supports an offline-first workflow for zero cost:
- KQL content is stored as files under `/detections-kql/` and `/workbooks/`
- Sample datasets and local harness can simulate alert outputs
- When Azure access becomes available, artifacts are directly portable into Sentinel for live screenshots and exports

---
