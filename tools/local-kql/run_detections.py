# tools/local-kql/run_detections.py
import json
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_SIGNIN = REPO_ROOT / "data" / "sample-logs" / "SigninLogs.jsonl"
DATA_AUDIT  = REPO_ROOT / "data" / "sample-logs" / "AuditLogs.jsonl"

OUT_DIR = REPO_ROOT / "data" / "demo-output"
ALERTS_PATH = OUT_DIR / "alerts.json"
INCIDENTS_DIR = OUT_DIR / "incident_contexts"

def _parse_time(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)

def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"Missing file: {path}\nRun generate_sample_logs.py first.")
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows

def _time_range(events: List[Dict[str, Any]]) -> tuple[str, str]:
    if not events:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return now, now
    ts = sorted([e["TimeGenerated"] for e in events])
    return ts[0], ts[-1]

# ---------------- DET-01 ----------------
def det01_failures_then_success(signins: List[Dict[str, Any]], fail_threshold: int = 10) -> List[Dict[str, Any]]:
    # group by IP
    by_ip: Dict[str, List[Dict[str, Any]]] = {}
    for e in signins:
        ip = e.get("IPAddress")
        if ip:
            by_ip.setdefault(ip, []).append(e)

    alerts = []
    for ip, events in by_ip.items():
        events.sort(key=lambda x: x["TimeGenerated"])
        failures = [e for e in events if int((e.get("Status") or {}).get("errorCode", 0)) != 0]
        successes = [e for e in events if int((e.get("Status") or {}).get("errorCode", 0)) == 0]
        if len(failures) >= fail_threshold and successes:
            first, last = _time_range(events)
            evidence = {
                "first_failures": [
                    {"time": failures[0]["TimeGenerated"], "user": failures[0]["UserPrincipalName"], "app": failures[0]["AppDisplayName"]},
                    {"time": failures[1]["TimeGenerated"], "user": failures[1]["UserPrincipalName"], "app": failures[1]["AppDisplayName"]},
                ],
                "success": {
                    "time": successes[0]["TimeGenerated"],
                    "user": successes[0]["UserPrincipalName"],
                    "app": successes[0]["AppDisplayName"]
                }
            }
            accounts = sorted({successes[0].get("UserPrincipalName")})
            country = ((successes[0].get("Location") or {}).get("countryOrRegion")) or None
            alerts.append({
                "detection_id": "DET-01",
                "title": "Multiple failures followed by success from same IP",
                "severity": "High",
                "entities": {"accounts": accounts, "ips": [ip], "country": country},
                "time_first": first,
                "time_last": last,
                "evidence": evidence
            })
    return alerts

# ---------------- DET-02 ----------------
def det02_legacy_auth(signins: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    hits = [e for e in signins if (e.get("ClientAppUsed") or "").lower().find("legacy") >= 0 and int((e.get("Status") or {}).get("errorCode", 0)) == 0]
    if not hits:
        return []
    hits.sort(key=lambda x: x["TimeGenerated"], reverse=True)
    top = hits[0]
    return [{
        "detection_id": "DET-02",
        "title": "Legacy Authentication sign-in detected",
        "severity": "Medium",
        "entities": {"accounts": [top.get("UserPrincipalName")], "ips": [top.get("IPAddress")]},
        "time_first": hits[-1]["TimeGenerated"],
        "time_last": hits[0]["TimeGenerated"],
        "evidence": {
            "sample_event": {
                "time": top.get("TimeGenerated"),
                "user": top.get("UserPrincipalName"),
                "app": top.get("AppDisplayName"),
                "ip": top.get("IPAddress"),
                "client_app_used": top.get("ClientAppUsed"),
            }
        }
    }]

# ---------------- DET-03 ----------------
def det03_new_country(signins: List[Dict[str, Any]], baseline_days: int = 14, recent_hours: int = 24, min_hits: int = 2) -> List[Dict[str, Any]]:
    # compute max time as "now"
    times = [_parse_time(e["TimeGenerated"]) for e in signins]
    now = max(times) if times else datetime.now(timezone.utc)
    recent_start = now - timedelta(hours=recent_hours)
    baseline_start = recent_start - timedelta(days=baseline_days)

    # baseline countries per user
    baseline: Dict[str, set] = {}
    for e in signins:
        t = _parse_time(e["TimeGenerated"])
        if baseline_start <= t < recent_start and int((e.get("Status") or {}).get("errorCode", 0)) == 0:
            u = e.get("UserPrincipalName")
            c = ((e.get("Location") or {}).get("countryOrRegion")) or None
            if u and c:
                baseline.setdefault(u, set()).add(c)

    # recent countries per user
    recent_counts: Dict[tuple, List[Dict[str, Any]]] = {}
    for e in signins:
        t = _parse_time(e["TimeGenerated"])
        if t >= recent_start and int((e.get("Status") or {}).get("errorCode", 0)) == 0:
            u = e.get("UserPrincipalName")
            c = ((e.get("Location") or {}).get("countryOrRegion")) or None
            if u and c:
                recent_counts.setdefault((u, c), []).append(e)

    alerts = []
    for (u, c), events in recent_counts.items():
        known = baseline.get(u, set())
        if c not in known and len(events) >= min_hits:
            events.sort(key=lambda x: x["TimeGenerated"])
            first, last = _time_range(events)
            ips = sorted({e.get("IPAddress") for e in events if e.get("IPAddress")})
            apps = sorted({e.get("AppDisplayName") for e in events if e.get("AppDisplayName")})
            alerts.append({
                "detection_id": "DET-03",
                "title": "New country sign-in for user (baseline vs recent)",
                "severity": "Medium",
                "entities": {"accounts": [u], "ips": ips, "country": c},
                "time_first": first,
                "time_last": last,
                "evidence": {
                    "baseline_countries": sorted(list(known)),
                    "new_country": c,
                    "recent_hits": len(events),
                    "sample": {"ips": ips, "apps": apps}
                }
            })
    return alerts

# ---------------- DET-04..07 (AuditLogs) helpers ----------------
def _audit_hits(audit: List[Dict[str, Any]], op_keywords: List[str]) -> List[Dict[str, Any]]:
    hits = []
    for e in audit:
        op = (e.get("OperationName") or "")
        res = (e.get("Result") or "")
        if res.lower() != "success":
            continue
        if any(k.lower() in op.lower() for k in op_keywords):
            hits.append(e)
    hits.sort(key=lambda x: x["TimeGenerated"], reverse=True)
    return hits

def det04_priv_role(audit: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    hits = _audit_hits(audit, ["role"])
    hits = [h for h in hits if (h.get("OperationName") or "").lower().find("role") >= 0]
    if not hits:
        return []
    top = hits[0]
    accounts = []
    initiator = (((top.get("InitiatedBy") or {}).get("user") or {}).get("userPrincipalName")) or None
    if initiator:
        accounts.append(initiator)
    return [{
        "detection_id": "DET-04",
        "title": "Privileged role assignment / role membership change",
        "severity": "High",
        "entities": {"accounts": accounts, "ips": []},
        "time_first": hits[-1]["TimeGenerated"],
        "time_last": hits[0]["TimeGenerated"],
        "evidence": {"sample_event": {"time": top["TimeGenerated"], "op": top.get("OperationName"), "correlationId": top.get("CorrelationId")}}
    }]

def det05_app_creds(audit: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    hits = _audit_hits(audit, ["credentials", "secret", "certificate", "key"])
    if not hits:
        return []
    top = hits[0]
    return [{
        "detection_id": "DET-05",
        "title": "Application/Service Principal credentials added/updated",
        "severity": "High",
        "entities": {"accounts": [(((top.get("InitiatedBy") or {}).get("user") or {}).get("userPrincipalName")) or "N/A"], "ips": []},
        "time_first": hits[-1]["TimeGenerated"],
        "time_last": hits[0]["TimeGenerated"],
        "evidence": {"sample_event": {"time": top["TimeGenerated"], "op": top.get("OperationName"), "target": (top.get("TargetResources") or [{}])[0].get("displayName")}}
    }]

def det06_consent(audit: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    hits = _audit_hits(audit, ["consent", "OAuth2", "permission grant"])
    if not hits:
        return []
    top = hits[0]
    return [{
        "detection_id": "DET-06",
        "title": "OAuth consent granted to application",
        "severity": "Medium",
        "entities": {"accounts": [(((top.get("InitiatedBy") or {}).get("user") or {}).get("userPrincipalName")) or "N/A"], "ips": []},
        "time_first": hits[-1]["TimeGenerated"],
        "time_last": hits[0]["TimeGenerated"],
        "evidence": {"sample_event": {"time": top["TimeGenerated"], "op": top.get("OperationName"), "app": (top.get("TargetResources") or [{}])[0].get("displayName")}}
    }]

def det07_mfa_change(audit: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    hits = _audit_hits(audit, ["security info", "authentication method", "MFA", "authenticator", "fido", "passwordless"])
    if not hits:
        return []
    top = hits[0]
    return [{
        "detection_id": "DET-07",
        "title": "MFA/security info changed",
        "severity": "High",
        "entities": {"accounts": [(((top.get("InitiatedBy") or {}).get("user") or {}).get("userPrincipalName")) or "N/A"], "ips": []},
        "time_first": hits[-1]["TimeGenerated"],
        "time_last": hits[0]["TimeGenerated"],
        "evidence": {"sample_event": {"time": top["TimeGenerated"], "op": top.get("OperationName"), "target": (top.get("TargetResources") or [{}])[0].get("displayName")}}
    }]

def write_outputs(alerts: List[Dict[str, Any]]) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    INCIDENTS_DIR.mkdir(parents=True, exist_ok=True)

    ALERTS_PATH.write_text(json.dumps(alerts, indent=2), encoding="utf-8")

    # Generate incident_context files that your enrichment tool already accepts
    for i, a in enumerate(alerts, start=1):
        ctx = {
            "incident_id": f"INC-{i:04d}",
            "title": a.get("title", "Sentinel incident"),
            "severity": a.get("severity", "Medium"),
            "time_start": a.get("time_first"),
            "time_end": a.get("time_last"),
            "detections": [a.get("detection_id")],
            "entities": {
                "accounts": (a.get("entities") or {}).get("accounts", []),
                "ips": (a.get("entities") or {}).get("ips", []),
            }
        }
        (INCIDENTS_DIR / f"INC-{i:04d}.json").write_text(json.dumps(ctx, indent=2), encoding="utf-8")

def main() -> None:
    print("Repo root:", REPO_ROOT)
    signins = load_jsonl(DATA_SIGNIN)
    audit = load_jsonl(DATA_AUDIT)

    alerts: List[Dict[str, Any]] = []
    alerts += det01_failures_then_success(signins)   # DET-01
    alerts += det02_legacy_auth(signins)             # DET-02
    alerts += det03_new_country(signins)             # DET-03
    alerts += det04_priv_role(audit)                 # DET-04
    alerts += det05_app_creds(audit)                 # DET-05
    alerts += det06_consent(audit)                   # DET-06
    alerts += det07_mfa_change(audit)                # DET-07

    print("\n=== Alerts ===")
    print(json.dumps(alerts, indent=2))

    write_outputs(alerts)
    print(f"\nWrote: {ALERTS_PATH}")
    print(f"Wrote incident contexts: {INCIDENTS_DIR}")

if __name__ == "__main__":
    main()
