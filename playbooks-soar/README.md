# SOAR Playbooks (Microsoft Sentinel + Logic Apps) — Offline-first

## Goal (portfolio signal)
These playbooks demonstrate “enterprise-ready” incident automation patterns for Microsoft Sentinel:
- Safe enrichment + ticketing (automatic)
- Manual-only containment (human-in-the-loop)

They are designed to be:
- **Production-minded** (least privilege, clear audit trail, avoids risky auto-containment)
- **Portable** (specs and templates in repo; export JSON when Azure access exists)
- **Aligned to detections/workbook** (DET-01..DET-07 + Identity Investigations workbook)

## Why incident trigger
Microsoft recommends the **Microsoft Sentinel incident trigger** for most automation scenarios because the playbook receives the incident object including alerts and entities. (Alert/entity triggers are mainly for manual use.)  
Refs: Microsoft Sentinel playbooks + supported triggers. :contentReference[oaicite:3]{index=3}

## Safety controls
- PB-01 is *enrichment + documentation only* (comments, ticket creation, notifications)
- PB-02 is *manual trigger only* for any containment actions (no autonomous disable)

## Deployment note
Logic Apps can incur costs when deployed. This repo is “offline-first” until a subscription is available. :contentReference[oaicite:4]{index=4}
