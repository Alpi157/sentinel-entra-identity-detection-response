# AI Triage Summary (Human-in-the-loop)

## Incident
- **Title:** DET-01 Multiple failures followed by success from same IP
- **Severity (source):** High
- **Time window:** 2026-01-23T13:30:00Z → 2026-01-23T14:10:00Z
- **Detections:** DET-01

## Entities
- **Accounts:** standard.user1@lab.local
- **IPs:** 203.0.113.77

## Confidence
- **Score:** 70/100 (Medium)
- **Rationale:**
  - DET-01 present (+35)
  - High failed sign-in volume for standard.user1@lab.local (failures=15) (+10)
  - Non-home country observed for standard.user1@lab.local (countries=['RU']) (+10)
  - IP has failures+success pattern (failures=15, successes=1) (+15)

## Evidence highlights
### Account summaries
- **standard.user1@lab.local**: total=16, success=1, failure=15, legacy_auth=0, countries=RU

### IP summaries
- **203.0.113.77**: failures=15, successes=1, targeted_users=1, countries=RU

### Notable audit events (time window)
- None observed in this time window.

## Recommended analyst actions (manual decision)
1) Pivot in the workbook: User timeline + Audit timeline for the primary account.
2) Validate whether activity matches an approved change or expected behavior.
3) If suspicious and approved: run **PB-02 Manual Containment** (no autonomous disable).
4) Document outcome + tuning notes in the case study.

## References
- **workbook:** /workbooks/identity-investigations/
- **detections:** /detections-kql/
- **runbook:** /docs/runbook.md
- **soar_pb01:** /playbooks-soar/PB-01-enrich-and-ticket/
- **soar_pb02:** /playbooks-soar/PB-02-manual-containment/