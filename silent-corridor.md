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

The account `s.brandt` had an unusually large number of remote access logs.

```kql
HuntData
| where MdeTable == "FortiGateVPN"
| summarize count() by AccountName
| sort by count_ desc 
```

<img width="259" height="114" alt="Screenshot 2026-05-19 175909" src="https://github.com/user-attachments/assets/96ba16cd-c0b0-4987-8af9-277dfd445600" />


### 2. Origin of Failed Auth

s.brandt's authentication logs show that it failed authentication when accessing from the IP `182.220.101.34`.

```kql
HuntData
| where MdeTable == "FortiGateVPN"
| where AccountName == "s.brandt"
| project EventTime, Message, RemoteIP
```

<img width="587" height="189" alt="Screenshot 2026-05-19 181001" src="https://github.com/user-attachments/assets/7defd96b-7044-40aa-9a96-5547d11729a0" />


### 3. Connection Footprint

```kql
HuntData
| where MdeTable == "FortiGateVPN"
| where AccountName == "s.brandt"
| summarize dcount(RemoteIP)
```

<img width="119" height="53" alt="Screenshot 2026-05-19 190928" src="https://github.com/user-attachments/assets/6172ebbb-3071-44af-8f4f-80a8deda640c" />

### 4. Source Address Inventory

```kql
HuntData
| where MdeTable == "FortiGateVPN"
| where AccountName == "s.brandt"
| distinct RemoteIP
```


<img width="136" height="133" alt="Screenshot 2026-05-19 191712" src="https://github.com/user-attachments/assets/12688473-9757-4e07-a794-f2c8fb21dd34" />

### 5. Internal Landing Point

```kql
HuntData
| where MdeTable == "FortiGateVPN"
| where AccountName == "s.brandt"
| distinct DestinationHost
```

<img width="132" height="68" alt="Screenshot 2026-05-19 191811" src="https://github.com/user-attachments/assets/55c3bf1f-a33c-416b-9045-cadd61b82280" />


### 6. Initial Process

Pivoting to beachhead and checking the first non-routine process under `s-brandt`'s session.

```kql
HuntData
| where MdeTable == "DeviceProcessEvents"
| where AccountName == "s.brandt"
| project EventTime, FileName, InitiatingProcessFileName
```

<img width="613" height="139" alt="Screenshot 2026-05-21 092007" src="https://github.com/user-attachments/assets/3283fe7f-b175-442d-862f-d1554c1c13a6" />


### 7. Directory Enumeration

Checking for AD enumeration commands.

```kql
HuntData
| where MdeTable == "DeviceProcessEvents"
| where AccountName == "s.brandt"
| project EventTime, ProcessCommandLine
```

<img width="570" height="218" alt="Screenshot 2026-05-21 092317" src="https://github.com/user-attachments/assets/961878ad-34ca-4c35-b476-816a5fb0fbf8" />


### 8. Network Reconnaissance

Mapping infrastructure

```kql
HuntData
| where AccountName == "s.brandt"
| where isnotempty(DnsQueryString)
| distinct DnsQueryString
```

<img width="229" height="111" alt="Screenshot 2026-05-21 092926" src="https://github.com/user-attachments/assets/ff13e3da-e8e3-4b64-8063-830ff420fd25" />


### 9. First Credential Activity

```kql
HuntData
| where AccountName == "s.brandt"
| where DeviceName  == "WS-ENG04"
| project EventTime, ProcessCommandLine
```

<img width="457" height="54" alt="Screenshot 2026-05-22 125050" src="https://github.com/user-attachments/assets/2646c9ba-e294-44ce-9e15-4eec782a1e8f" />


### 10. Credential Dump Outcome

```kql
HuntData
| where EventTime startswith "2026-02-26"
| where FileName == "rundll32.exe" or FolderPath startswith "C:\\Windows\\Temp"
| project EventTime, ActionType, FileName, FolderPath, ProcessCommandLine
```

<img width="1401" height="143" alt="Screenshot 2026-05-22 131144" src="https://github.com/user-attachments/assets/adf7c714-1ca1-481e-b051-a4f969d36240" />


### 11. Stored Credential Source

```kql
HuntData
| where FileName == "reg.exe" and ProcessCommandLine has "save"
| project EventTime, FileName, ProcessCommandLine
```

<img width="725" height="84" alt="Screenshot 2026-05-22 131527" src="https://github.com/user-attachments/assets/76da0561-9493-4cd1-9c2c-96be17bcc8d5" />


### 12. Saved Credentials

```kql
HuntData
| where AccountName == "s.brandt"
| where DeviceName  == "WS-ENG04"
| where ProcessCommandLine has "list"
| project EventTime, ProcessCommandLine
```

<img width="736" height="111" alt="Screenshot 2026-05-22 131748" src="https://github.com/user-attachments/assets/b2d5a0c7-cec4-4372-a0ff-c57f11c45411" />


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
