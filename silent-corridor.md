## Operation: Silent Corridor

BfV (German federal intelligence) has issued a confidential advisory to defence sector organisations. A state-sponsored actor designated GREY VEIL has been conducting intrusions against European aerospace and defence contractors since late 2025. Their primary objectives are intellectual property theft and persistent access to engineering networks. Previous victims reported extended dwell times before detection.

Haldric Aerospace is a Tier 2 defence contractor specialising in avionics navigation systems for European military programmes. Engineering staff work from a dedicated network segment with remote access via SSL VPN. The company employs approximately 200 staff across three sites.

## Timeline & Queries Used

### 0. Environment Access

This is the base filter used at the top of every query.

```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| sort by EventTime asc;
```

### 1. Suspicious Account

The previous victims were compromised through remote access infrastructure. Comparing authentication volumes across all VPN accounts reveals that the account s.brandt has an unusually large amount of logs.

```kql
HuntData
| where MdeTable == "FortiGateVPN"
| summarize count() by AccountName
| sort by count_ desc 
```

<img width="259" height="114" alt="Screenshot 2026-05-19 175909" src="https://github.com/user-attachments/assets/96ba16cd-c0b0-4987-8af9-277dfd445600" />

### 2. Origin of Failed Auth

### 3. Connection Footprint

### 4. Source Address Inventory

### 5. Internal Landing Point

### 6. Initial Process

### 7. Directory Enumeration

### 8. Network Reconnaissance

### 9. First Credential Activity

### 10. Credential Dump Outcome

### 11. Stored Credential Source

### 12. Saved Credentials

### 13. First Lateral Pivot

### 14. New Account Observed

### 15. Cross-Host Spawning

### 16. New Filesystem Activity

### 17. Critical File

### 18. Concurrent File Access

### 19. Database File Access

### 20. Spawning Source

### 21. RDP Scope

### 22. Network Configuration Change

### 23. Configuration Storage

### 24. Matching Configuration on DC

### 25. Targeted Directory

### 26. Packaged Output

### 27. Compression Method

### 28. Format Conversion

### 29. Outbound Transfer

### 30. External Destination

### 31. Reentry Window

### 32. First Cleanup Action

### 34. Clearing Method Analysis

### 35. Exfiltration Confidence Call

### 36. DC Staging Cleanup

### 37. CISO Brief
