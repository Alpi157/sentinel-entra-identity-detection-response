import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[3]
SIGNIN_PATH = REPO_ROOT / "data" / "sample-logs" / "SigninLogs.jsonl"
AUDIT_PATH  = REPO_ROOT / "data" / "sample-logs" / "AuditLogs.jsonl"

def _parse_time(s: str) -> datetime:
    # Format used in our sample logs: 2026-01-23T13:55:30Z
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)

def _load_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"Missing {path}. Run tools/local-kql/generate_sample_logs.py first.")
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows

class OfflineProvider:
    """
    Offline evidence provider that reads Entra-shaped sample data from:
    - data/sample-logs/SigninLogs.jsonl
    - data/sample-logs/AuditLogs.jsonl
    """

    def __init__(self) -> None:
        self.signins = _load_jsonl(SIGNIN_PATH)
        self.audit = _load_jsonl(AUDIT_PATH)

    def _in_range(self, t: str, start: datetime, end: datetime) -> bool:
        dt = _parse_time(t)
        return start <= dt <= end

    def recent_signins_for_user(self, upn: str, start: datetime, end: datetime, limit: int = 50) -> List[Dict[str, Any]]:
        rows = [
            r for r in self.signins
            if r.get("UserPrincipalName") == upn and self._in_range(r["TimeGenerated"], start, end)
        ]
        rows.sort(key=lambda x: x["TimeGenerated"], reverse=True)
        return rows[:limit]

    def signin_summary_for_user(self, upn: str, start: datetime, end: datetime) -> Dict[str, Any]:
        rows = [
            r for r in self.signins
            if r.get("UserPrincipalName") == upn and self._in_range(r["TimeGenerated"], start, end)
        ]
        success = sum(1 for r in rows if int(r.get("Status", {}).get("errorCode", 0)) == 0)
        failure = sum(1 for r in rows if int(r.get("Status", {}).get("errorCode", 0)) != 0)
        countries = sorted({(r.get("Location") or {}).get("countryOrRegion") for r in rows if r.get("Location")})
        ips = sorted({r.get("IPAddress") for r in rows if r.get("IPAddress")})
        apps = sorted({r.get("AppDisplayName") for r in rows if r.get("AppDisplayName")})
        legacy = sum(1 for r in rows if (r.get("ClientAppUsed") or "").lower().find("legacy") >= 0)

        return {
            "user": upn,
            "total": len(rows),
            "success": success,
            "failure": failure,
            "legacy_auth_count": legacy,
            "countries": countries,
            "ips": ips,
            "apps": apps,
        }

    def ip_summary(self, ip: str, start: datetime, end: datetime) -> Dict[str, Any]:
        rows = [r for r in self.signins if r.get("IPAddress") == ip and self._in_range(r["TimeGenerated"], start, end)]
        failures = sum(1 for r in rows if int(r.get("Status", {}).get("errorCode", 0)) != 0)
        successes = sum(1 for r in rows if int(r.get("Status", {}).get("errorCode", 0)) == 0)
        users = sorted({r.get("UserPrincipalName") for r in rows if r.get("UserPrincipalName")})
        countries = sorted({(r.get("Location") or {}).get("countryOrRegion") for r in rows if r.get("Location")})
        apps = sorted({r.get("AppDisplayName") for r in rows if r.get("AppDisplayName")})

        return {
            "ip": ip,
            "total": len(rows),
            "failures": failures,
            "successes": successes,
            "targeted_users_count": len(users),
            "users": users[:20],
            "countries": countries,
            "apps": apps[:20],
        }

    def audit_events(self, start: datetime, end: datetime, limit: int = 50) -> List[Dict[str, Any]]:
        rows = [r for r in self.audit if self._in_range(r["TimeGenerated"], start, end)]
        rows.sort(key=lambda x: x["TimeGenerated"], reverse=True)
        return rows[:limit]
