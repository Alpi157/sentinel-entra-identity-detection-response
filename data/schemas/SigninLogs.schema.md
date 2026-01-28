# SigninLogs (Sample Schema)

This repo uses a sample dataset shaped to match commonly-used fields of Microsoft Sentinel's `SigninLogs` table.
It enables local KQL development and reproducible demos without requiring an Azure subscription.

## Key fields used by detections/workbook
- TimeGenerated (datetime)
- UserPrincipalName (string)
- UserId (string)
- AppDisplayName (string)
- IPAddress (string)
- Location (dynamic/string: country/region/city)
- DeviceDetail (dynamic: browser, operatingSystem, deviceId)
- Status (dynamic: errorCode, failureReason, additionalDetails)
- ConditionalAccessStatus (string)
- AuthenticationRequirement (string)
- ClientAppUsed (string)
- UserAgent (string)
