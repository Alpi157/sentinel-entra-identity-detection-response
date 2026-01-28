import argparse
import json
from pathlib import Path
from datetime import datetime, timezone

def load_bundle(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"Bundle not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))

def score_bundle(bundle: dict) -> dict:
    """
    Deterministic, zero-cost scoring model.
    Produces: confidence (0-100) + rationale list.
    """
    incident = bundle.get("incident", {})
    evidence = bundle.get("evidence", {})
    detections = incident.get("detections", []) or []

    score = 0
    rationale = []

    # Map detections to weights (tunable)
    weights = {
        "DET-01": 35,  # failures then success from same IP
        "DET-02": 15,  # legacy auth
        "DET-03": 20,  # new country
        "DET-04": 40,  # privileged role assignment
        "DET-05": 40,  # app credentials added
        "DET-06": 30,  # OAuth consent grant
        "DET-07": 35,  # MFA/security info changed
    }

    for d in detections:
        if d in weights:
            score += weights[d]
            rationale.append(f"{d} present (+{weights[d]})")

    # Evidence-based boosts
    acct_summaries = evidence.get("account_summaries", []) or []
    ip_summaries = evidence.get("ip_summaries", []) or []

    for a in acct_summaries:
        failures = int(a.get("failure", 0))
        legacy = int(a.get("legacy_auth_count", 0))
        countries = a.get("countries", []) or []
        if failures >= 10:
            score += 10
            rationale.append(f"High failed sign-in volume for {a.get('user')} (failures={failures}) (+10)")
        if legacy > 0:
            score += 10
            rationale.append(f"Legacy auth observed for {a.get('user')} (+10)")
        if len(countries) >= 1 and any(c and c != "CA" for c in countries):
            score += 10
            rationale.append(f"Non-home country observed for {a.get('user')} (countries={countries}) (+10)")

    for ip in ip_summaries:
        failures = int(ip.get("failures", 0))
        successes = int(ip.get("successes", 0))
        targeted = int(ip.get("targeted_users_count", 0))
        if failures >= 10 and successes >= 1:
            score += 15
            rationale.append(f"IP has failures+success pattern (failures={failures}, successes={successes}) (+15)")
        if targeted >= 5:
            score += 15
            rationale.append(f"IP targeted many users (targeted_users={targeted}) (+15)")

    # Clamp score
    score = max(0, min(score, 100))

    # Convert to a label
    if score >= 80:
        label = "High"
    elif score >= 50:
        label = "Medium"
    else:
        label = "Low"

    return {"confidence_score": score, "confidence_label": label, "rationale": rationale}

def summarize(bundle: dict) -> str:
    incident = bundle.get("incident", {})
    entities = bundle.get("entities", {})
    evidence = bundle.get("evidence", {})
    links = bundle.get("links", {})

    detections = incident.get("detections", []) or []
    accounts = entities.get("accounts", []) or []
    ips = entities.get("ips", []) or []

    scoring = score_bundle(bundle)

    acct_summaries = evidence.get("account_summaries", []) or []
    ip_summaries = evidence.get("ip_summaries", []) or []
    audit_events = evidence.get("audit_events", []) or []

    def fmt_list(items):
        return ", ".join(items) if items else "N/A"

    lines = []
    lines.append(f"# AI Triage Summary (Human-in-the-loop)")
    lines.append("")
    lines.append("## Incident")
    lines.append(f"- **Title:** {incident.get('title','N/A')}")
    lines.append(f"- **Severity (source):** {incident.get('severity','N/A')}")
    lines.append(f"- **Time window:** {incident.get('time_start','N/A')} → {incident.get('time_end','N/A')}")
    lines.append(f"- **Detections:** {fmt_list(detections)}")
    lines.append("")
    lines.append("## Entities")
    lines.append(f"- **Accounts:** {fmt_list(accounts)}")
    lines.append(f"- **IPs:** {fmt_list(ips)}")
    lines.append("")
    lines.append("## Confidence")
    lines.append(f"- **Score:** {scoring['confidence_score']}/100 ({scoring['confidence_label']})")
    lines.append("- **Rationale:**")
    if scoring["rationale"]:
        for r in scoring["rationale"][:10]:
            lines.append(f"  - {r}")
    else:
        lines.append("  - No scoring rationale available.")

    lines.append("")
    lines.append("## Evidence highlights")
    lines.append("### Account summaries")
    if acct_summaries:
        for a in acct_summaries:
            lines.append(f"- **{a.get('user','N/A')}**: total={a.get('total',0)}, success={a.get('success',0)}, failure={a.get('failure',0)}, legacy_auth={a.get('legacy_auth_count',0)}, countries={fmt_list(a.get('countries',[]))}")
    else:
        lines.append("- N/A")

    lines.append("")
    lines.append("### IP summaries")
    if ip_summaries:
        for ip in ip_summaries:
            lines.append(f"- **{ip.get('ip','N/A')}**: failures={ip.get('failures',0)}, successes={ip.get('successes',0)}, targeted_users={ip.get('targeted_users_count',0)}, countries={fmt_list(ip.get('countries',[]))}")
    else:
        lines.append("- N/A")

    lines.append("")
    lines.append("### Notable audit events (time window)")
    if audit_events:
        for e in audit_events[:8]:
            lines.append(f"- {e.get('TimeGenerated','N/A')} — **{e.get('OperationName','N/A')}** ({e.get('Result','N/A')})")
    else:
        lines.append("- None observed in this time window.")

    lines.append("")
    lines.append("## Recommended analyst actions (manual decision)")
    lines.append("1) Pivot in the workbook: User timeline + Audit timeline for the primary account.")
    lines.append("2) Validate whether activity matches an approved change or expected behavior.")
    lines.append("3) If suspicious and approved: run **PB-02 Manual Containment** (no autonomous disable).")
    lines.append("4) Document outcome + tuning notes in the case study.")

    lines.append("")
    lines.append("## References")
    if links:
        for k, v in links.items():
            lines.append(f"- **{k}:** {v}")
    else:
        lines.append("- N/A")

    return "\n".join(lines)

def main():
    ap = argparse.ArgumentParser(description="Generate a structured triage summary from an investigation bundle.")
    ap.add_argument(
        "--in",
        dest="in_path",
        default="enrichment-graph/sample-output/investigation-bundle.sample.json",
        help="Path to investigation bundle JSON",
    )
    ap.add_argument(
        "--out",
        dest="out_path",
        default="ai-triage-summarizer/sample-output/triage-summary.sample.md",
        help="Output Markdown path",
    )
    args = ap.parse_args()

    bundle = load_bundle(Path(args.in_path))
    md = summarize(bundle)

    out_path = Path(args.out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(md, encoding="utf-8")
    print(f"Wrote: {out_path}")

if __name__ == "__main__":
    main()
