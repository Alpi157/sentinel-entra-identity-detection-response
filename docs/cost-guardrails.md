# Cost Guardrails (Goal: $0)

## Why this stays free
- Microsoft Sentinel offers a 31-day free trial for new workspaces: first 10 GB/day ingested is free.  
- We will set a Log Analytics daily cap so ingestion stops if anything spikes.

## Hard rules
1) Only ingest Entra ID Sign-in Logs + Audit Logs (no VM agents, no network flow logs).
2) Set Log Analytics daily cap to the minimum practical value.
3) After screenshots + exports, delete the Azure Resource Group.

## Cleanup
Delete the resource group to stop all costs immediately.
