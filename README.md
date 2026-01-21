# Identity Threat Detection & Response Lab (Microsoft Sentinel + Entra ID)  
**Optional AI Triage Summary (Human-in-the-loop)**

## What it does
- Ingests Microsoft Entra ID sign-in + audit logs into Microsoft Sentinel.
- Detects high-signal identity threats with KQL analytics rules + MITRE mapping.
- Supports investigation with a dedicated “Identity Investigations” workbook.
- Automates enrichment + ticket/notification via SOAR playbooks (safe automation).
- (Optional) Generates an AI-written incident summary for analyst approval (no autonomous containment).

## Stack
Microsoft Sentinel • Microsoft Entra ID • KQL • Azure Logic Apps (SOAR) • Microsoft Graph • Python

## Outcomes
- 5–8 documented KQL detections with tuning + false-positive guidance
- 1 investigation workbook dashboard
- 1–2 SOAR playbooks (enrichment + manual containment)
- Python enrichment tool that builds an “investigation bundle” (JSON)
- Case study: alert → triage → decision → response

## Architecture
> (Add diagram in /assets/architecture.png)

## Demo (60–120s)
> (Add video link)

## Screenshots
- Workbook dashboard
- Example incident
- Example KQL rule

## Repo layout
- `/detections-kql/` KQL rules + documentation
- `/workbooks/` exported workbook JSON + screenshots
- `/playbooks-soar/` Logic Apps exports + diagrams
- `/enrichment-graph/` Python Graph enrichment tool + sample output
- `/ai-triage/` optional summarizer (human approval required)
- `/case-study/` short incident report

## Safety & cost guardrails
This lab is designed to be run at $0 using the Microsoft Sentinel 31-day free trial and a strict Log Analytics daily cap. See: `docs/cost-guardrails.md`.
