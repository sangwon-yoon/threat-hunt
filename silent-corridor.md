# Operation: Silent Corridor

BfV (German federal intelligence) has issued a confidential advisory to defence sector organisations. A state-sponsored actor designated GREY VEIL has been conducting intrusions against European aerospace and defence contractors since late 2025. Their primary objectives are intellectual property theft and persistent access to engineering networks. Previous victims reported extended dwell times before detection.

Haldric Aerospace is a Tier 2 defence contractor specialising in avionics navigation systems for European military programmes. Engineering staff work from a dedicated network segment with remote access via SSL VPN. The company employs approximately 200 staff across three sites.

This is a proactive hunt. There are no alerts. No indicators of compromise have been provided. You are hunting based on the advisory alone. Determine whether GREY VEIL has accessed Haldric Aerospace infrastructure. If they have, scope the full extent of the compromise.

## Platforms and Languages Leveraged

* Log Analytics Workspace
* Kusto Query Language (KQL)

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

```kql
HuntData
| where AccountName == "s.brandt"
| where DeviceName  == "WS-ENG04"
| project EventTime, ProcessCommandLine
```

<img width="565" height="47" alt="Screenshot 2026-05-22 132158" src="https://github.com/user-attachments/assets/fa72cd15-b48e-43fd-8f5b-b125ee96ed9c" />

```kql
HuntData
| where MdeTable == "FortiGateVPN"
| where EventTime startswith "2026-02-28"
| project EventTime, TunnelIP
```

<img width="302" height="48" alt="Screenshot 2026-05-22 133012" src="https://github.com/user-attachments/assets/6b162e1b-c30f-4cf1-bb9a-58b36fb468ef" />


### 14. New Account Observed

m.richter

### 15. Cross-Host Spawning

```kql
HuntData
| where ProcessCommandLine has "/node:"
| project EventTime, FileName, ProcessCommandLine
```

<img width="1256" height="224" alt="Screenshot 2026-05-22 133650" src="https://github.com/user-attachments/assets/f89c8063-0bdd-43db-ab7c-30582b5c76ca" />


### 16. New Filesystem Activity

```kql
HuntData
| where DeviceName == "SRV-DC01"
| where ActionType == "FileCreated"
| where FolderPath startswith "C:\\Windows\\Temp"
| project FileName, FolderPath
```

<img width="521" height="164" alt="Screenshot 2026-05-22 134132" src="https://github.com/user-attachments/assets/9a685ef4-b25f-47fa-b3f8-b3cdf1fd5690" />


### 17. Critical File

```kql
HuntData
| where FileName == "ntds.dit"
| project FileName, InitiatingProcessAccountName
```

<img width="393" height="54" alt="Screenshot 2026-05-22 134327" src="https://github.com/user-attachments/assets/73fc3228-4a29-43c7-add8-5dfcb7c14924" />


### 18. Concurrent File Access

```kql
HuntData
| where FileName == "ntds.dit"
| project FileName, InitiatingProcessFileName
```

<img width="368" height="84" alt="Screenshot 2026-05-22 134443" src="https://github.com/user-attachments/assets/179169d7-936b-4b8f-b29b-ecfcc7c56f76" />


### 19. Database File Access

```kql
HuntData
| where DeviceName == "SRV-DC01"
| where AccountName == "m.richter"
| where ProcessCommandLine has "McAfee"
| project EventTime, FileName, ProcessCommandLine
```

<img width="849" height="113" alt="Screenshot 2026-05-22 134808" src="https://github.com/user-attachments/assets/ebf02be8-86ed-4e9b-a688-b9f554b488a6" />


### 20. Spawning Source

```kql
HuntData
| where DeviceName == "SRV-DC01"
| where AccountName == "m.richter"
| project EventTime, FileName, ProcessCommandLine, InitiatingProcessFileName
```

<img width="813" height="80" alt="Screenshot 2026-05-22 135348" src="https://github.com/user-attachments/assets/e308902a-5086-4437-89fe-5a2ad616c9f8" />


### 21. RDP Scope

```kql
HuntData
| where MdeTable == "DeviceNetworkEvents"
| where RemoteIP == "10.1.96.114"
| distinct DeviceName
```

<img width="117" height="110" alt="Screenshot 2026-05-22 135859" src="https://github.com/user-attachments/assets/e0cff4ae-4140-45c5-b391-6e17f2168001" />


### 22. Network Configuration Change

```kql
HuntData
| where DeviceName == "WS-ENG04"
| where ProcessCommandLine has "netsh"
| project EventTime, ProcessCommandLine
```

<img width="981" height="134" alt="Screenshot 2026-05-22 155525" src="https://github.com/user-attachments/assets/b6b39df6-89e9-4c2a-b8fa-4f0556ff9b57" />


### 23. Configuration Storage

```kql
HuntData
| where DeviceName == "WS-ENG04"
| where MdeTable == "DeviceRegistryEvents"
| where InitiatingProcessFileName == "netsh.exe"
| project EventTime, RegistryKey
```

<img width="606" height="62" alt="Screenshot 2026-05-22 155731" src="https://github.com/user-attachments/assets/8709d3d7-82d0-4f5a-a280-2740a49f0eeb" />


### 24. Matching Configuration on DC

```kql
HuntData
| where DeviceName == "SRV-DC01"
| where ProcessCommandLine has "netsh"
| project EventTime, ProcessCommandLine
```

<img width="993" height="87" alt="Screenshot 2026-05-22 155822" src="https://github.com/user-attachments/assets/f772db58-d958-4bf6-87c6-db3892b1b88b" />


### 25. Targeted Directory

C:\Engineering\Avionics\A400M_NavSys\

```kql
HuntData
| where DeviceName == "SRV-FILES02"
| where AccountName == "m.richter"
| project EventTime, ProcessCommandLine
```

<img width="1049" height="106" alt="Screenshot 2026-05-22 160031" src="https://github.com/user-attachments/assets/59401104-461f-434b-9e9f-f3aaab06d818" />


### 26. Packaged Output

win_update_kb5034.zip

### 27. Compression Method

Compress-Archive

### 28. Format Conversion

certutil

<img width="815" height="89" alt="Screenshot 2026-05-22 160746" src="https://github.com/user-attachments/assets/55b6140c-5830-42a1-8328-839f535b0b8f" />


### 29. Outbound Transfer

```kql
HuntData
| where DeviceName == "WS-ENG04"
| where AccountName == "s.brandt"
| project EventTime, ProcessCommandLine
```

<img width="1140" height="50" alt="Screenshot 2026-05-22 160957" src="https://github.com/user-attachments/assets/2823b121-90f2-4847-b7fb-41682740de6c" />


### 30. External Destination

cdn-telemetry.cloud-endpoint.net

### 31. Reentry Window

<img width="771" height="24" alt="Screenshot 2026-05-22 161136" src="https://github.com/user-attachments/assets/6939e316-1770-49f3-9ec4-3bf73789bb92" />


### 32. First Cleanup Action

```kql
HuntData
| where DeviceName == "WS-ENG04"
| where AccountName == "s.brandt"
| where ProcessCommandLine has "cl"
| project EventTime, ProcessCommandLine, InitiatingProcessFileName
```

<img width="1095" height="138" alt="Screenshot 2026-05-22 162054" src="https://github.com/user-attachments/assets/420fe41c-270e-44ef-a059-c7157209c9d4" />



### 33. Clearing Method Analysis

```kql
HuntData
| where DeviceName == "SRV-DC01"
| where AccountName == "m.richter"
| where ProcessCommandLine has "cl"
| project EventTime, ProcessCommandLine, InitiatingProcessFileName
```

<img width="603" height="139" alt="Screenshot 2026-05-22 162154" src="https://github.com/user-attachments/assets/d32f3128-dc88-4baf-9e49-8bdf8550e62d" />


```kql
HuntData
| where DeviceName == "SRV-FILES02"
| where AccountName == "m.richter"
| where ProcessCommandLine has "cl"
| project EventTime, ProcessCommandLine, InitiatingProcessFileName
```

<img width="599" height="139" alt="Screenshot 2026-05-22 162210" src="https://github.com/user-attachments/assets/53e1f209-512d-4a19-bf40-203199804b80" />

### 34. Surviving Log Source

Sysmon

### 35. Exfiltration Confidence Call

HIGH. C:\Engineering\Avionics\A400M_NavSys\ was compressed into win_update_kb5034.zip, encoded via certutil to a base64 file, and POSTed to cdn-telemetry.cloud-endpoint.net.

### 36. DC Staging Cleanup

<img width="532" height="50" alt="Screenshot 2026-05-22 162459" src="https://github.com/user-attachments/assets/4e3d8e23-8d45-49be-a988-9c2788ab7083" />

### 37. CISO Brief

Accounts s.brandt and m.richter as well as hosts WS-ENG04, SRV-DC01, and SRV-FILES02 were compromised. The targeted data was located in 'C:\Engineering\Avionics\A400M_NavSys\' which was zipped and POSTed to cdn-telemetry.cloud-endpoint.net. The attackers achieved persistence by editing the registry to set up port forwarding through credential resets. The compromised hosts should be isolated from the network immediately.
