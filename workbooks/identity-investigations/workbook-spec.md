# Identity Investigations Workbook (Entra + Sentinel)

## Summary 
This workbook is a SOC-style **Identity Investigation console** designed for Microsoft Sentinel + Microsoft Entra ID telemetry. It converts raw identity logs into an investigation experience that supports:

- **Triage fast:** what’s happening right now (failures, legacy auth, risky changes)
- **Investigate consistently:** user/IP timelines + country/app pivots
- **Respond responsibly:** surfaces evidence needed for SOAR enrichment + human approval workflows

**Data sources:** `SigninLogs`, `AuditLogs`  
**Aligned detections:** DET-01 → DET-07 (repo `/detections-kql/`)  
**Design goal:** High-signal, low-noise panels with parameter-driven drilldowns and performance-friendly aggregation.

---

## Why this exists (SOC workflow)
Identity incidents usually follow a predictable flow:

1) **Signal appears** (alert / anomaly / suspicious change)
2) **Scope the blast radius** (who, where, how many, how often)
3) **Pivot the investigation** (user ↔ IP ↔ app ↔ country)
4) **Confirm change control** (audit events: roles, OAuth consent, credentials, MFA methods)
5) **Decide and respond** (document evidence, enrich, notify, contain manually if needed)

This workbook intentionally mirrors that flow.

---

## Workbook parameters (interactive controls)
> These parameters are created in the Sentinel Workbook editor (“Add parameters”) and are referenced in panel KQL.

### Required
- **TimeRange** *(time range picker)*  
  Default: Last 24 hours (support: 7d, 14d, custom)

### Optional (investigation pivots)
- **UserUPN** *(text input)*  
  Filter investigation panels to a specific user (UPN).
- **IPAddress** *(text input)*  
  Filter investigation panels to a specific source IP.
- **Country** *(dropdown, from query)*  
  For geographic pivot views.
- **App** *(dropdown, from query)*  
  For application pivot views.

### Optional (performance control)
- **ShowRawTables** *(toggle: Off/On — default Off)*  
  Workbooks can return large tables; raw-event panels should only be expanded when needed.

---

## Layout (recommended page structure)

### Section A — Executive SOC Overview (1–2 minutes to understand posture)
Purpose: give analysts (and reviewers) immediate situational awareness and “where to look next.”

Panels:
1. **01-kpis.kql** — KPI tiles  
   *Outputs:* total sign-ins, failed sign-ins, legacy auth sign-ins, high-risk audit counts (roles, creds, consent, MFA)
2. **02-signins-trend.kql** — sign-in success vs failure trend (timechart)
3. **05-signins-by-country.kql** — sign-ins by country (bar)
4. **03-top-failing-users.kql** — top users by failed sign-in count (table)
5. **04-top-offending-ips.kql** — top IPs by failures + distinct users targeted (table)

**Analyst use:** identify spikes, hotspots, and likely investigation entry points.

---

### Section B — Detection Drilldowns (maps 1:1 to repo detections)
Purpose: show “alert logic” as investigation-ready outputs.

Panels:
6. **06-det-01-failures-then-success.kql** — DET-01 (failures → success from same IP)  
   *Why it matters:* credential guessing/spray pattern with eventual success.
7. **07-det-02-legacy-auth.kql** — DET-02 (legacy auth sign-in)  
   *Why it matters:* legacy clients are frequently targeted and often disallowed in mature tenants.
8. **08-det-03-new-country.kql** — DET-03 (new country vs baseline)  
   *Why it matters:* common indicator of compromised credentials / unexpected travel.

**Analyst use:** select a row → pivot to Section D (User/IP investigation).

---

### Section C — Audit Change Control (high-signal identity governance events)
Purpose: detect and investigate high-impact identity configuration changes.

Panels:
9. **09-det-04-priv-role.kql** — DET-04 (privileged role assignment)  
   *Why it matters:* privilege escalation / unauthorized admin access.
10. **10-det-05-app-cred.kql** — DET-05 (app/service principal credential added)  
   *Why it matters:* persistence via secrets/certs.
11. **11-det-06-consent.kql** — DET-06 (OAuth consent grant)  
   *Why it matters:* OAuth persistence / data access.
12. **12-det-07-mfa-changes.kql** — DET-07 (MFA/security info changes)  
   *Why it matters:* account takeover follow-on; attacker attempts to lock in access.

**Analyst use:** confirm whether changes are authorized and correlate with sign-in anomalies.

---

### Section D — Investigation Pivots (User/IP focused)
Purpose: provide a standard playbook for evidence gathering.

Panels:
13. **13-user-timeline.kql** — Sign-in timeline filtered by `UserUPN`  
    *Use:* confirm sign-in pattern, apps, IPs, CA status, failures/successes.
14. **14-user-audit.kql** — Audit timeline filtered by `UserUPN`  
    *Use:* confirm role/credential/consent/MFA changes near the time of suspicious sign-ins.

**Optional additions (future enhancement):**
- IP pivot panel (“All users from selected IP over TimeRange”)
- App pivot panel (“All users for selected AppDisplayName over TimeRange”)

---

## Investigation workflow (how to use this workbook during an incident)

### Triage path (fast)
1) Set **TimeRange = Last 24h**
2) Review **KPI tiles** and **Sign-in trend**
3) Identify hotspots from:
   - Top offending IPs
   - Top failing users
   - Legacy auth sign-ins
4) Open relevant detection drilldown (DET-01/02/03) and select the most suspicious row

### Deep-dive path (repeatable)
5) Copy the **UserPrincipalName** into **UserUPN**
6) Review:
   - User sign-in timeline (what changed, where, and when)
   - User audit timeline (role, consent, credentials, MFA changes)
7) Decide:
   - **Escalate** (high confidence compromise)
   - **Contain** (manual approval workflow)
   - **Close** with documented reasoning (benign false positive)

---

## Performance and production considerations
This workbook is designed to be safe and scalable:

- **Time filter first:** every panel scopes by `TimeRange` early to reduce compute.
- **Summarize for overview:** dashboard panels use `summarize`, not raw event dumps.
- **Limit row count:** top-N tables cap results and reduce noise.
- **Raw payload visibility:** audit panels retain `TargetResources` for investigation, but are still time-scoped.
- **Parameter-driven pivots:** avoids manual query edits and standardizes analyst workflow.

---

## Evidence outputs (what gets used by SOAR + enrichment tools)
This workbook is intentionally aligned with the project’s next steps:

- **SOAR enrichment playbook** will take incident entities (UserUPN/IP) from workbook-driven triage.
- **Graph enrichment tool** will build an investigation bundle (JSON) using the same pivots:
  - recent sign-ins
  - role membership / changes
  - OAuth consent / app credentials events
  - MFA method changes

The workbook provides the “human context” for what to enrich and why.

---

## Screenshots to capture (for README + portfolio)
When running in a real Sentinel environment (or when you later get access), capture:

1) **Overview:** KPI tiles + sign-in trend (Section A)
2) **Detection drilldown:** DET-01 or DET-04 table showing suspicious row
3) **Investigation:** User timeline + Audit timeline for the same entity

Store in: `workbooks/screenshots/`
- `workbook-overview.png`
- `workbook-detection-drilldown.png`
- `workbook-user-investigation.png`

---

## Export / artifact management
When deployed in Azure/Sentinel:
- Export the workbook JSON from the workbook editor and commit it under:
  - `workbooks/identity-investigations/identity-investigations.workbook.json`

Offline-first (current mode):
- The workbook is represented as a spec + panel KQL files so the logic is reviewable and portable.

---

## Changelog (optional but recommended)
- v1: Initial workbook with identity overview, detection drilldowns (DET-01..07), and user audit/sign-in pivots.
- vNext: IP pivot panel, app pivot panel, allowlist watchlists, and incident deep links.
