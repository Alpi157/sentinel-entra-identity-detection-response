# AuditLogs (Sample Schema)

This repo uses a sample dataset shaped to match commonly-used fields of Microsoft Sentinel's `AuditLogs` table.

## Key fields used by detections/workbook
- TimeGenerated (datetime)
- OperationName (string)
- Result (string)
- InitiatedBy (dynamic: user/app)
- TargetResources (dynamic array: type, id, displayName, modifiedProperties)
- AdditionalDetails (dynamic array)
- CorrelationId (string)
