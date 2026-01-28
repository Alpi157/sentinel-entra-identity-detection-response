# PB-02 — Manual Containment (Human Approved Only)

## Objective
Provide a manual, analyst-triggered playbook that:
1) Confirms the entities (user/IP) for the incident
2) Posts a containment checklist comment
3) (Optional future) calls a containment action endpoint (Graph/Defender) ONLY after explicit approval

This playbook intentionally avoids autonomous “disable user” behavior.

## Trigger
Microsoft Sentinel incident trigger, but configured and documented as:
- **Manual run by analyst on an incident**

Playbooks can be run manually on incidents/alerts/entities, and incident triggers are intended for incident automation scenarios. :contentReference[oaicite:11]{index=11}

## Steps
1) Extract entities: target account(s), suspicious IP(s)
2) Add a “Containment Decision” comment to the incident:
   - What containment options exist
   - What evidence must be verified
   - Who approved
3) Optional (future): If approved, execute containment action(s):
   - Disable sign-in / revoke sessions
   - Remove privileged role assignment
   - Revoke OAuth consent / disable service principal

## Safety controls
- Manual trigger only
- Explicit approval required (documented in comment)
- Comment includes “what evidence justified containment”

## Output
- Clear incident comment that documents the containment decision and actions taken
- (Future) optional containment action result appended to incident comments
