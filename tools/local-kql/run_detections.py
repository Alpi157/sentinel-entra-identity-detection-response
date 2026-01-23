# tools/local-kql/run_detections.py
import json
from pathlib import Path

# Always resolve paths relative to the repo root (works no matter where you run it from)
REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_SIGNIN = REPO_ROOT / "data" / "sample-logs" / "SigninLogs.jsonl"
DATA_AUDIT  = REPO_ROOT / "data" / "sample-logs" / "AuditLogs.jsonl"

def load_jsonl(path: Path):
    if not path.exists():
        raise FileNotFoundError(
            f"Missing file: {path}\n"
            f"Fix: run generate_sample_logs.py first, or check that the repo has data/sample-logs/."
        )
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows

def detection_failures_then_success(signins, ip="203.0.113.77", fail_threshold=10):
    """
    Demo detection: many failed sign-ins from same IP + at least one success from same IP.
    This aligns with the KQL rule we'll write in Step 3.
    """
    events = [e for e in signins if e.get("IPAddress") == ip]
    events.sort(key=lambda x: x["TimeGenerated"])

    failures = [e for e in events if e.get("Status", {}).get("errorCode", 0) != 0]
    successes = [e for e in events if e.get("Status", {}).get("errorCode", 0) == 0]

    if len(failures) >= fail_threshold and successes:
        return [{
            "title": "Multiple failures followed by success from same IP",
            "ip": ip,
            "failure_count": len(failures),
            "example_user": successes[0].get("UserPrincipalName"),
            "time_first": events[0].get("TimeGenerated"),
            "time_last": events[-1].get("TimeGenerated")
        }]
    return []

def main():
    print("Repo root:", REPO_ROOT)
    print("Loading:", DATA_SIGNIN)
    print("Loading:", DATA_AUDIT)

    signins = load_jsonl(DATA_SIGNIN)
    _audit  = load_jsonl(DATA_AUDIT)

    alerts = []
    alerts += detection_failures_then_success(signins)

    print("\n=== Alerts ===")
    if not alerts:
        print("(none)")
    else:
        for a in alerts:
            print(json.dumps(a, indent=2))

if __name__ == "__main__":
    main()
