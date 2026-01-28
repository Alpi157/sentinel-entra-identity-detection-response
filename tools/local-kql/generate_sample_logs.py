# tools/local-kql/generate_sample_logs.py
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(7)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# Reproducible "now" so screenshots/demos don't change every run
NOW = datetime(2026, 1, 23, 14, 10, 0, tzinfo=timezone.utc)

# Generate enough history for baseline detections (DET-03)
HISTORY_DAYS = 21
start = NOW - timedelta(days=HISTORY_DAYS)

users = [
    {"upn": "standard.user1@lab.local", "id": "u-001", "home_country": "CA"},
    {"upn": "standard.user2@lab.local", "id": "u-002", "home_country": "CA"},
    {"upn": "sec.analyst@lab.local",    "id": "u-003", "home_country": "CA"},
    {"upn": "it.admin@lab.local",       "id": "u-004", "home_country": "CA"},
]

apps = ["Microsoft Teams", "Microsoft 365 Portal", "Azure Portal", "SharePoint Online"]
user_agents = [
    "Mozilla/5.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
]

def sign_in_event(
    dt: datetime,
    user: dict,
    ok: bool = True,
    country: str = "CA",
    legacy: bool = False,
    ip: str | None = None,
    error_code: int | None = None,
    reason: str | None = None,
) -> dict:
    if ip is None:
        ip = f"192.0.2.{random.randint(10,200)}" if country == "CA" else f"198.51.100.{random.randint(10,200)}"

    status = {"errorCode": 0, "failureReason": None, "additionalDetails": None}
    if not ok:
        status = {
            "errorCode": error_code if error_code is not None else 50126,
            "failureReason": reason if reason else "Invalid username or password",
            "additionalDetails": "MFA required" if random.random() < 0.2 else None,
        }

    return {
        "TimeGenerated": iso(dt),
        "UserPrincipalName": user["upn"],
        "UserId": user["id"],
        "AppDisplayName": random.choice(apps),
        "IPAddress": ip,
        "Location": {"countryOrRegion": country, "city": "Vancouver" if country == "CA" else "Unknown"},
        "DeviceDetail": {
            "operatingSystem": "Windows",
            "browser": "Chrome",
            "deviceId": f"dev-{random.randint(100,999)}",
        },
        "Status": status,
        "ConditionalAccessStatus": "success" if ok else "failure",
        "AuthenticationRequirement": "multiFactorAuthentication" if random.random() < 0.5 else "singleFactorAuthentication",
        "ClientAppUsed": "Legacy Authentication" if legacy else "Browser",
        "UserAgent": random.choice(user_agents),
    }

def audit_event(
    dt: datetime,
    op: str,
    initiated_upn: str,
    target_type: str,
    target_name: str,
    result: str = "success",
    extra: list | None = None,
) -> dict:
    return {
        "TimeGenerated": iso(dt),
        "OperationName": op,
        "Result": result,
        "InitiatedBy": {"user": {"userPrincipalName": initiated_upn}},
        "TargetResources": [
            {
                "type": target_type,
                "displayName": target_name,
                "modifiedProperties": extra or [],
            }
        ],
        "AdditionalDetails": [],
        "CorrelationId": f"corr-{random.randint(100000,999999)}",
    }

signin: list[dict] = []
audit: list[dict] = []

# --- Baseline: normal sign-ins across HISTORY_DAYS (CA)
# Each day each non-admin user signs in a few times (mostly success)
for day in range(HISTORY_DAYS):
    day_base = start + timedelta(days=day)
    for user in users[:3]:
        n = random.randint(2, 5)
        for i in range(n):
            dt = day_base + timedelta(hours=random.randint(8, 20), minutes=random.randint(0, 59))
            ok = True if random.random() > 0.08 else False  # small background failure rate
            signin.append(sign_in_event(dt, user, ok=ok, country=user["home_country"]))

# --- DET-01 scenario: many failures then success (same IP), from RU
victim = users[0]
spray_time = NOW - timedelta(hours=6)
attacker_country = "RU"
spray_ip = "203.0.113.77"
for i in range(15):
    signin.append(
        sign_in_event(
            spray_time + timedelta(minutes=i),
            victim,
            ok=False,
            country=attacker_country,
            ip=spray_ip,
        )
    )
signin.append(
    sign_in_event(
        spray_time + timedelta(minutes=20),
        victim,
        ok=True,
        country=attacker_country,
        ip=spray_ip,
    )
)

# --- DET-02 scenario: legacy auth usage (successful)
legacy_user = users[1]
legacy_time = NOW - timedelta(hours=12)
signin.append(sign_in_event(legacy_time, legacy_user, ok=True, country="CA", legacy=True))

# --- DET-03 scenario: new country sign-ins that repeat (2 hits) for same user (baseline is CA)
traveler = users[2]
new_country_time = NOW - timedelta(hours=10)
new_country_ip = "198.51.100.44"
signin.append(sign_in_event(new_country_time, traveler, ok=True, country="RU", ip=new_country_ip))
signin.append(sign_in_event(new_country_time + timedelta(minutes=20), traveler, ok=True, country="RU", ip=new_country_ip))

# --- DET-04 privileged role assignment (AuditLogs)
admin = users[3]
audit_time = NOW - timedelta(hours=5)
audit.append(
    audit_event(
        audit_time,
        "Add member to role",
        admin["upn"],
        "Role",
        "Global Administrator",
        extra=[{"displayName": "RoleAssignment", "newValue": victim["upn"], "oldValue": ""}],
    )
)

# --- DET-05 app credential added (persistence)
audit.append(
    audit_event(
        NOW - timedelta(hours=4),
        "Add service principal credentials",
        admin["upn"],
        "ServicePrincipal",
        "Contoso-App",
        extra=[{"displayName": "KeyDescription", "newValue": "New client secret", "oldValue": ""}],
    )
)

# --- DET-06 consent granted (OAuth)
audit.append(
    audit_event(
        NOW - timedelta(hours=3),
        "Consent to application",
        victim["upn"],
        "Application",
        "Suspicious-OAuth-App",
        extra=[{"displayName": "Scopes", "newValue": "Mail.Read Files.Read.All", "oldValue": ""}],
    )
)

# --- DET-07 MFA/security info changed
audit.append(
    audit_event(
        NOW - timedelta(hours=2),
        "User updated security info",
        victim["upn"],
        "User",
        victim["upn"],
        extra=[{"displayName": "AuthenticationMethod", "newValue": "Microsoft Authenticator added", "oldValue": ""}],
    )
)

# --- Output paths (always write into repo/data/sample-logs regardless of current working directory)
repo_root = Path(__file__).resolve().parents[2]
out_dir = repo_root / "data" / "sample-logs"
out_dir.mkdir(parents=True, exist_ok=True)

signin_path = out_dir / "SigninLogs.jsonl"
audit_path = out_dir / "AuditLogs.jsonl"

with open(signin_path, "w", encoding="utf-8") as f:
    for e in sorted(signin, key=lambda x: x["TimeGenerated"]):
        f.write(json.dumps(e) + "\n")

with open(audit_path, "w", encoding="utf-8") as f:
    for e in sorted(audit, key=lambda x: x["TimeGenerated"]):
        f.write(json.dumps(e) + "\n")

print("Generated sample logs:")
print(f"- {signin_path}")
print(f"- {audit_path}")
print(f"History days: {HISTORY_DAYS} (NOW fixed at {iso(NOW)})")
