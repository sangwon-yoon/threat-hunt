## Operation: Silent Corridor

BfV (German federal intelligence) has issued a confidential advisory to defence sector organisations. A state-sponsored actor designated GREY VEIL has been conducting intrusions against European aerospace and defence contractors since late 2025. Their primary objectives are intellectual property theft and persistent access to engineering networks. Previous victims reported extended dwell times before detection.

Haldric Aerospace is a Tier 2 defence contractor specialising in avionics navigation systems for European military programmes. Engineering staff work from a dedicated network segment with remote access via SSL VPN. The company employs approximately 200 staff across three sites.

```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| sort by EventTime asc;
HuntData
| where AccountName == "m.richter"
| where DeviceName == "SRV-FILES02"
| where MdeTable == "DeviceProcessEvents"
```
