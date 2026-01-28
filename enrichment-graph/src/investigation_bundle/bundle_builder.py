from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from dateutil.parser import isoparse

from .offline_provider import OfflineProvider

def _dt(s: str) -> datetime:
    # supports ISO8601 with Z
    dt = isoparse(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

@dataclass
class IncidentContext:
    incident_id: str
    title: str
    severity: str
    time_start: str
    time_end: str
    detections: List[str]
    accounts: List[str]
    ips: List[str]

def build_investigation_bundle_offline(ctx: IncidentContext) -> Dict[str, Any]:
    provider = OfflineProvider()
    start = _dt(ctx.time_start)
    end = _dt(ctx.time_end)

    account_summaries = [provider.signin_summary_for_user(u, start, end) for u in ctx.accounts]
    ip_summaries = [provider.ip_summary(ip, start, end) for ip in ctx.ips]

    recent_signins = {}
    for u in ctx.accounts:
        recent_signins[u] = provider.recent_signins_for_user(u, start, end, limit=50)

    audit = provider.audit_events(start, end, limit=50)

    recommendations: List[str] = [
        "Review Identity Investigations workbook: User timeline + Audit timeline for primary account.",
        "Validate whether any privileged changes (roles/consent/credentials/MFA) occurred near the incident time.",
        "If suspicious and approved: execute PB-02 Manual Containment steps (disable user sign-in, revoke sessions, revoke consent, remove role assignments).",
        "Document outcome and tuning notes in the case study."
    ]

    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "mode": "offline",
        "incident": {
            "id": ctx.incident_id,
            "title": ctx.title,
            "severity": ctx.severity,
            "time_start": ctx.time_start,
            "time_end": ctx.time_end,
            "detections": ctx.detections
        },
        "entities": {
            "accounts": ctx.accounts,
            "ips": ctx.ips
        },
        "evidence": {
            "account_summaries": account_summaries,
            "ip_summaries": ip_summaries,
            "recent_signins": recent_signins,
            "audit_events": audit
        },
        "recommended_actions": recommendations,
        "links": {
            "workbook": "/workbooks/identity-investigations/",
            "detections": "/detections-kql/",
            "runbook": "/docs/runbook.md",
            "soar_pb01": "/playbooks-soar/PB-01-enrich-and-ticket/",
            "soar_pb02": "/playbooks-soar/PB-02-manual-containment/"
        }
    }
