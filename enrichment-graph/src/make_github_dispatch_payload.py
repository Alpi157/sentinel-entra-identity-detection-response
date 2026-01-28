import argparse
import json
from pathlib import Path
from datetime import datetime, timezone

def _repo_tool_root() -> Path:
    # This file lives at enrichment-graph/src/make_github_dispatch_payload.py
    return Path(__file__).resolve().parents[1]  # enrichment-graph/

def _safe_get(d, *keys, default=None):
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur

def _fmt_account_summary(s: dict) -> str:
    return (
        f"- **{s.get('user','N/A')}**: total={s.get('total',0)} "
        f"(success={s.get('success',0)}, failure={s.get('failure',0)}), "
        f"legacy_auth={s.get('legacy_auth_count',0)}, "
        f"countries={', '.join(s.get('countries',[]) or []) or 'N/A'}"
    )

def _fmt_ip_summary(s: dict) -> str:
    return (
        f"- **{s.get('ip','N/A')}**: total={s.get('total',0)} "
        f"(failures={s.get('failures',0)}, successes={s.get('successes',0)}), "
        f"targeted_users={s.get('targeted_users_count',0)}, "
        f"countries={', '.join(s.get('countries',[]) or []) or 'N/A'}"
    )

def _fmt_audit_events(events: list) -> str:
    if not events:
        return "- None in time window"
    lines = []
    for e in events[:8]:
        t = e.get("TimeGenerated", "N/A")
        op = e.get("OperationName", "N/A")
        res = e.get("Result", "N/A")
        initiator = _safe_get(e, "InitiatedBy", "user", "userPrincipalName", default=None) or "N/A"
        lines.append(f"- {t} — **{op}** ({res}) — initiator: {initiator}")
    return "\n".join(lines)

def build_dispatch_payload(bundle: dict) -> dict:
    incident = bundle.get("incident", {})
    entities = bundle.get("entities", {})
    evidence = bundle.get("evidence", {})

    accounts = entities.get("accounts", []) or []
    ips = entities.get("ips", []) or []

    acct_summaries = evidence.get("account_summaries", []) or []
    ip_summaries = evidence.get("ip_summaries", []) or []
    audit_events = evidence.get("audit_events", []) or []

    enrichment_lines = []
    enrichment_lines.append("### Account Summary")
    enrichment_lines.extend([_fmt_account_summary(s) for s in acct_summaries] or ["- N/A"])
    enrichment_lines.append("")
    enrichment_lines.append("### IP Summary")
    enrichment_lines.extend([_fmt_ip_summary(s) for s in ip_summaries] or ["- N/A"])
    enrichment_lines.append("")
    enrichment_lines.append("### Notable Audit Events")
    enrichment_lines.append(_fmt_audit_events(audit_events))

    payload = {
        "event_type": "sentinel_ticket",
        "client_payload": {
            "incidentTitle": incident.get("title", "Sentinel incident"),
            "severity": incident.get("severity", "Medium"),
            "time": incident.get("time_end") or bundle.get("generated_at") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "accounts": accounts,
            "ips": ips,
            "detections": incident.get("detections", []),
            "enrichment": "\n".join(enrichment_lines)
        }
    }
    return payload

def main():
    tool_root = _repo_tool_root()
    default_in = tool_root / "sample-output" / "investigation-bundle.sample.json"
    default_out = tool_root / "sample-output" / "github-dispatch-payload.json"

    ap = argparse.ArgumentParser(description="Create a GitHub repository_dispatch payload from an investigation bundle.")
    ap.add_argument("--in", dest="in_path", default=str(default_in), help="Path to investigation bundle JSON")
    ap.add_argument("--out", dest="out_path", default=str(default_out), help="Output path for dispatch payload JSON")
    args = ap.parse_args()

    in_path = Path(args.in_path)
    out_path = Path(args.out_path)

    if not in_path.exists():
        raise FileNotFoundError(f"Input bundle not found: {in_path}")

    bundle = json.loads(in_path.read_text(encoding="utf-8"))
    payload = build_dispatch_payload(bundle)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Wrote: {out_path}")

if __name__ == "__main__":
    main()
