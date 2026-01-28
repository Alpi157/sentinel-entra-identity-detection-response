# Graph Enrichment Tool — Investigation Bundle (Offline-first, Live-ready)

## What it does
Builds a structured **investigation bundle JSON** for identity incidents:
- entity summaries (accounts, IPs)
- recent sign-in evidence
- relevant audit events (roles/consent/credentials/MFA)
- recommended analyst actions + links to workbook/detections/runbook

## Why it matters
This mirrors a real SOC workflow: detections trigger an incident, and automation enriches it with evidence so analysts can decide quickly.

## Modes
- **Offline mode (default):** reads Entra-shaped sample logs from `/data/sample-logs/`
- **Live Graph mode (future):** will call Microsoft Graph for real tenant data using MSAL auth (same output schema)

## Run (offline)
From repo root:

```bash
pip install -r enrichment-graph/requirements.txt
python enrichment-graph/src/main.py
```

---
