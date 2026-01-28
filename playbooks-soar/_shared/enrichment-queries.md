# PB-01 Enrichment Queries (KQL Pack)

## Purpose
These queries are used by PB-01 (Enrich & Ticket) to attach fast, high-signal context to an incident.
They are designed to be:
- parameterized (UPN, IP)
- time-scoped (TimeRange / lookback)
- summarized (performance-friendly)

---

## Inputs
- `UserUPN` (string) — user principal name (optional)
- `IPAddress` (string) — source IP (optional)
- `lookback` (timespan) — default 24h

---

## Q1 — User sign-in summary (last 24h)
```kql
let lookback = 24h;
let u = "{UserUPN}";
SigninLogs
| where TimeGenerated >= ago(lookback)
| where isempty(u) or UserPrincipalName == u
| summarize
    Total=count(),
    Success=countif(toint(Status.errorCode) == 0),
    Failure=countif(toint(Status.errorCode) != 0),
    Countries=make_set(tostring(Location.countryOrRegion), 10),
    IPs=make_set(IPAddress, 10),
    Apps=make_set(AppDisplayName, 10),
    FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated)
  by UserPrincipalName
| order by Failure desc
```

## Q2 — Recent sign-in timeline (for evidence)
```kql
let lookback = 24h;
let u = "{UserUPN}";
SigninLogs
| where TimeGenerated >= ago(lookback)
| where isempty(u) or UserPrincipalName == u
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, Location, ClientAppUsed, ConditionalAccessStatus, Status
| order by TimeGenerated desc
| take 50
```

## Q3 — IP activity summary (blast radius)
```kql
let lookback = 24h;
let ip = "{IPAddress}";
SigninLogs
| where TimeGenerated >= ago(lookback)
| where isempty(ip) or IPAddress == ip
| summarize
    Total=count(),
    Failures=countif(toint(Status.errorCode) != 0),
    Successes=countif(toint(Status.errorCode) == 0),
    TargetedUsers=dcount(UserPrincipalName),
    Users=make_set(UserPrincipalName, 20),
    Countries=make_set(tostring(Location.countryOrRegion), 10),
    Apps=make_set(AppDisplayName, 10),
    FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated)
  by IPAddress
```

## Q4 — High-impact AuditLogs for user (roles/consent/creds/MFA)
```kql
let lookback = 7d;
let u = "{UserUPN}";
AuditLogs
| where TimeGenerated >= ago(lookback)
| where isempty(u) or tostring(InitiatedBy.user.userPrincipalName) == u
| where OperationName has_any ("role", "Consent", "credential", "password", "secret", "certificate", "key", "security info", "authentication method", "MFA")
| project TimeGenerated, OperationName, Result, InitiatedBy, TargetResources, CorrelationId
| order by TimeGenerated desc
| take 50
```


## Q5 — DET quick-match (useful for ticket summary)
```kql
let lookback = 24h;
let u = "{UserUPN}";
let ip = "{IPAddress}";

let det01 =
    SigninLogs
    | where TimeGenerated >= ago(lookback)
    | where isempty(ip) or IPAddress == ip
    | summarize Failures=countif(toint(Status.errorCode) != 0), Successes=countif(toint(Status.errorCode) == 0), Users=dcount(UserPrincipalName) by IPAddress
    | where Failures >= 10 and Successes >= 1
    | project Detection="DET-01", Detail=strcat("Failures=", tostring(Failures), " Successes=", tostring(Successes), " Users=", tostring(Users));

let det02 =
    SigninLogs
    | where TimeGenerated >= ago(lookback)
    | where isempty(u) or UserPrincipalName == u
    | where ClientAppUsed has "Legacy Authentication"
    | project Detection="DET-02", Detail=strcat("Legacy auth sign-in: ", AppDisplayName, " from ", IPAddress);

let det04to07 =
    AuditLogs
    | where TimeGenerated >= ago(7d)
    | where isempty(u) or tostring(InitiatedBy.user.userPrincipalName) == u
    | where OperationName has_any ("role", "Consent", "credential", "security info", "authentication method", "MFA")
    | project Detection="AuditSignal", Detail=OperationName;

union det01, det02, det04to07
| take 50
```






