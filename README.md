# Threat-Hunt-Remote-Assistance
# 🕵️‍♂️ Threat Hunt: *"Remote Assistance"*

## Scenario

> *"A routine support request should have ended with a reset and reassurance. Instead, the so-called “help”
left behind a trail of anomalies that don’t add up."*

What was framed as troubleshooting looked more like an audit of the system itself — probing, cataloging,
leaving subtle traces in its wake. Actions chained together in suspicious sequence: first gaining a foothold,
then expanding reach, then preparing to linger long after the session ended.
And just when the activity should have raised questions, a neat explanation appeared — a story planted in
plain sight, designed to justify the very behavior that demanded scrutiny.
This wasn’t remote assistance. It was a misdirection.
Your mission this time is to reconstruct the timeline, connect the scattered remnants of this “support
session”, and decide what was legitimate, and what was staged.
The evidence is here. The question is whether you’ll see through the story or believe it.

This report includes:

- 📅 Timeline reconstruction of auditing, reconnaissance, and attempted exfiltration of data on the device **`gab-intern-vm`**
- 📜 Detailed queries using Microsoft Defender Advanced Hunting (KQL)
- 🎯 MITRE ATT&CK mapping to understand TTP alignment
- 🧪 Evidence-based summaries supporting each flag and behavior discovered

---

## 🧰 Platforms and Tools

**Analysis Environment:**
- Microsoft Defender for Endpoint
- Log Analytics Workspace
- Azure

**Techniques Used:**
- Kusto Query Language (KQL)
- Behavioral analysis of endpoint logs (DeviceProcessEvents, DeviceNetworkEvents, DeviceRegistryEvents)

---

## 📔 Summary of Findings (Flags)

| Flag | Objective | Finding | TimeStamp |
|------|------------------------|---------|-----------|
| 0 | Starting Point: Suspicious Processes Spawning in Downloads | `gab-intern-vm` was the first targeted machine | `2025-10-09T12:22:27.6514901Z` |
| 1 | Initial Execution Detection | `-ExecutionPolicy` was the earliest anomalous execution | `2025-10-09T12:22:27.6514901Z` |
| 2 | Defense Disabling | `DefenderTamperArtifact.lnk` was created in relation to the exploit | `2025-10-09T12:34:59.1260624Z` |
| 3 | Quick Data Probe | `"powershell.exe" -NoProfile -Sta -Command` contained a `Get-Clipboard` to attempt to collect transient info  | `2025-10-09T12:50:39.955931Z` |
| 4 | Host Context Recon | At `2025-10-09T12:51:44.3425653Z` the Processs Command Line `qwinsta.exe` was executed | `2025-10-09T12:51:44.3425653Z` |
| 5 | Storage Surface Mapping | `"cmd.exe" /c wmic logicaldisk get name,freespace,size` query was indicative of storage surface mapping | `2025-10-09T12:51:18.3848072Z` |
| 6 | Connectivity & Name Resolution Check | `RuntimeBroker.exe` was the initiating parent process for DNS queries | `2025-10-09T12:51:44.3081129Z` |
| 7 | Interactive Session Discovery | The unique ID of the initiating process was found to be `2533274790397065 ` | `2025-10-09T12:51:44.3081129Z` |
| 8 | Runtime Application Inventory | `tasklist.exe` was the filename of the runtime process enumeration event on the target host | `2025-10-09T12:51:57.6866149Z` |
| 9 | Privilege Surface Check | The first use of CLI commands for discovery was at `2025-10-09T12:52:14.3135459Z` | `2025-10-09T12:52:14.3135459Z` |
| 10 | Proof-of-Access & Egress Validation | `www.msftconnecttest.com` was the first suspicious outbound destination | `2025-10-09T12:55:15.736717Z` |
| 11 | Bundling / Staging Artifacts | Folder path value where the artifact was first dropped into: `C:\Users\Public\ReconArtifacts.zip` | `2025-10-09T12:59:05.6804726Z` |
| 12 | Outbound Transfer Attempt (Simulated) | Last unusual outbound connection: `100.29.147.161` | `2025-10-09T13:00:40.7259181Z` |
| 13 | Scheduled Re-Execution Persistence | Creation of task `SupportToolUpdater` was found to be associated with scheduled re-execution | `2025-10-09T13:01:28.7700443Z` |
| 14 | Autorun Fallback Persistence | `RemoteAssistUpdater` was the name of the registry value |  |
| 15 | Planted Narrative / Cover Artifact | `SupportChat_log.lnk` was the artifact left behind | `2025-10-09T13:02:41.5698148Z` |

---
### 🚩 Flag 0: Starting Point - Suspicious Processes Spawning in Downloads

**Objective:**
Determine where to start hunting with the following intel:
1. Multiple machines in the department started spawning processes originating from the download folders.
This unexpected scenario occurred during the first half of October.
2. Several machines were found to share the same types of files — similar executables, naming patterns,
and other traits.
3. Common keywords among the discovered files included “desk,” “help,” “support,” and “tool.”
4. Intern operated machines seem to be affected to certain degree.

**Flag Value:**
`gab-intern-vm`
`2025-10-09T12:22:27.6514901Z`

**Detection Strategy:**
Multiple alerts were issued indicating that multiple machines were spawning processes originating from the "downloads" folders around the first half of October (10/01/2025 - 10/15/2025). Common keywords among the discovered files included "desk", "help", "support", and "tool". The following query was used in Microsoft Defender to find any files associated with the keywords:

**KQLQuery:**
```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where FileName matches regex @"(?i)(desk|help|support|tool)"
| where FolderPath has @"\Downloads\"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA1, InitiatingProcessAccountName
| order by TimeGenerated desc
```
**Evidence:**

<img width="1902" height="359" alt="image" src="https://github.com/user-attachments/assets/12e8effd-bd58-40e4-9d45-8d1fc05ac0db" />

The initial query showed suspicious files that were downloaded with the keywords in the alert. The affected device was identified as `gab-intern-vm`.

**Why This Matters:**
The query allowed us to narrow down the affected machines that may be responsible for the alert.

---

### 🚩 Flag 1: Initial Execution Detection

**Objective:**
Detect the earliest anomalous execution that could represent an entry point.

**Flag Value:**
`-ExecutionPolicy`
`2025-10-09T12:22:27.6514901Z`

**Detection Strategy:**
In order to find the earliest anomalous execution, the query needed to be fine-tuned to look for suspicious Command Line Interface (CLI) parameters. The suspicious file was created at `2025-10-09T12:22:27.6514901Z` and named "SupportTool.ps1". Using this time frame to narrow down results, the DeviceProcessEvents query can be adjusted accordingly.

**KQLQuery:**

```kql
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessFileName =~ "powershell.exe"
| where TimeGenerated between (datetime(2025-10-09T12:00:00Z) .. datetime(2025-10-09T12:30:00Z))
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Evidence:**
<img width="1699" height="220" alt="image" src="https://github.com/user-attachments/assets/2ec6d32d-6ade-4e54-b420-435c7d793d16" />

**Why This Matters:**
The first Command Line Interface Process originating from the suspicious file within the Downloads directory can lead the investigation into new paths. Collection of evidence and signs of intent will be easier to find if the parent files and processes are known.

---

### 🚩 Flag 2: Defense Disabling

**Objective:**
Identify indicators that suggest attempts to imply or simulate changing security posture.

**Flag Value:**
`DefenderTamperArtifact.lnk`
`2025-10-09T12:34:59.1260624Z`

**Detection Strategy:**
The previous results gave a timeframe of when the initial process was executed. Knowing that the possibility of any indications of attempts or changes to the security postue would be present after the timeframe of `2025-10-09T12:22:27.6514901Z`, the query was adjusted to after the known initial process. Any file creation, modifications, or copies would be scrutinized for any alarming behaviors.

**KQLQuery:**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime('2025-10-09T12:22:27.6588913Z') .. datetime(2025-10-10))
| where DeviceName == "gab-intern-vm"
| where ActionType in ("FileCreated","FileModified","FileCopied")
| order by TimeGenerated asc
```

**Evidence:**
<img width="2083" height="492" alt="image" src="https://github.com/user-attachments/assets/be7574d0-f065-4af1-827f-0238510a9877" />

**Why This Matters:**
An artifact creation or short-lived process that contains tamper-related contents found to be related to the exploit can indicate intent of changing mitigation. The file 'DefenderTamperArtifact.lnk' is proof of intent.

---

### 🚩 Flag 3: Quick Data Probe

**Objective:**
Spot brief, opportunistic checks for readily available sensitive content.

**Flag Value:**
`"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"`
`2025-10-09T12:50:39.955931Z`

**Detection Strategy:**
Attackers often look for low effort wins first. Quick probes such as these can often precede broader reconnaissance. Adjustments should be made to search for transient data such as anything related to "clip" or "clipboard".

**KQLQuery:**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where ProcessCommandLine has_any ("clip.exe","Get-Clipboard","Set-Clipboard","Out-Clipboard"," | clip")
| summarize count() by ProcessCommandLine, DeviceName, InitiatingProcessFileName
```

**Evidence:**
<img width="1217" height="218" alt="image" src="https://github.com/user-attachments/assets/310def0c-c35c-4bfb-97ac-e7a596e80949" />

**Why This Matters:**
The attempts at probing for readily available sensitive content such as the "clipboard" can show evidence for intent for opportunistic checks.

---

### 🚩 Flag 4: Host Context Recon

**Objective:**
Find activity that gathers basic host and user context to inform follow-up actions.

**Flag Value:**
`2025-10-09T12:51:44.3425653Z`

**Detection Strategy:**
Activity related to queries for context and reconnaissance shape attack decisions such as "who", "what", and "where" to target objectives. By looking for Proccess Command Line inputs for typical host recon commands such as "whoami", "systeminfo", "ipconfig", "query user", "quser", "qwinsta", etc, the proof for recon can be obtained.

**KQLQuery:**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any ("whoami", "hostname", "systeminfo", "ipconfig", "ipconfig /all", "net user", "net localgroup", "query user", "quser", "qwinsta", "wmic", "Get-ComputerInfo", "Get-CimInstance",
 "Get-WmiObject", "Get-NetIPConfiguration", "Get-NetAdapter", "Get-NetIPAddress", "Get-Process", "tasklist", "netstat -ano", "reg query", "Get-Service", "Get-LocalUser", "Get-ChildItem Env:")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
| order by TimeGenerated desc
```
**Evidence:**
<img width="1266" height="251" alt="image" src="https://github.com/user-attachments/assets/8dbc8e44-3926-4959-940f-deb8e14ae564" />

**Why This Matters:**
Attempts that try to identify information about the host can be observed as reconnaissance and treated collected as evidence. The attacker has shown interest in discovering information about the host which can lead to attempts are understanding the scope or attack surface.

---

### 🚩 Flag 5: Storage Surface Mapping

**Objective:**
Detect discovery of local or network storage locations that might hold interesting data.

**Flag Value:**
`"cmd.exe" /c wmic logicaldisk get name,freespace,size`
`2025-10-09T12:51:18.3848072Z`

**Detection Strategy:**
Any enumeration of filesystem, share surfaces, and lightweight checks of available storaged would indicate attempts for storage surface mapping. Searching for any ProcessCommandLine and quick "read-only" commands such as "net view", "dir", "Get-PSDrive", "wmic logicaldisk" with connections to network share queries like "net view \\HOST” or “Get-SmbShare" would show explicit network share discovery.

**KQLQuery:**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any ( "Get-ChildItem","Get-PSDrive","Get-Volume","Get-SmbShare","Get-SmbMapping", "net view","net share","net use","dir ","wmic logicaldisk","fsutil volume diskfree", "mountvol","robocopy /L")
| order by DeviceName asc, TimeGenerated asc
| project DeviceName, TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
```

**Evidence:**
<img width="1378" height="279" alt="image" src="https://github.com/user-attachments/assets/bcdf7a3b-4d3b-45dd-9d9e-51dd9e5bfb16" />

**Why This Matters:**
In this instance, a query for the disk name, available space, and total volume size shows intent to assess the storage information on the host device which further supports intent for surface mapping.

---

### 🚩 Flag 6: Connectivity & Name Resolution Check

**Objective:**
Identify checks that validate network reachability and name resolution.

**Flag Value:**
`RuntimeBroker.exe`
`2025-10-09T12:51:44.3081129Z`

**Detection Strategy:**
Network or process events indicating DNS or interface queries and simple outward connectivity probes.

**KQLQuery:**
```kql
union isfuzzy=true 
DeviceProcessEvents, DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any ("ping", "nslookup", "Test-NetConnection", "Resolve-DnsName", "Get-NetIPConfiguration", "session")
      or RemoteUrl has_any ("dns", "lookup", "session")
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName, ActionType
| order by TimeGenerated asc
```
**Evidence:**
<img width="1858" height="321" alt="image" src="https://github.com/user-attachments/assets/d5f40d59-3753-4a08-9c81-974c8939d5b6" />

**Why This Matters:**
Confirmation of egress is a necessity before any attempts to move data off-host. After establishing a connection, exfiltrated data can be transferred. "RuntimeBroker.exe" was found to to be the initiating parent process for the queries.

---

### 🚩 Flag 7: Interactive Session Discovery

**Objective:**
Reveal attempts to detect interactive or active user sessions on the host.

**Flag Value:**
`2533274790397065`
`2025-10-09T12:51:44.3081129Z`

**Detection Strategy:**
In a previous query, the process "qwinsta.exe" was found to have enumerated the current session state or logged-in session of the host device. Using this knowledge, investigations for the unique ID of the initiating process can begin based off the command line process.

**KQLQuery:**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any ("query user", "qwinsta", "net session", "Get-WmiObject Win32_LoggedOnUser", "Get-CimInstance Win32_ComputerSystem", "query session", "Get-WmiObject", "Get-CimInstance")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId, InitiatingProcessParentId, InitiatingProcessUniqueId
| order by TimeGenerated asc
```

**Evidence:**
<img width="2104" height="348" alt="image" src="https://github.com/user-attachments/assets/eb534628-b072-4470-8c3b-39e5e15a7e0f" />

**Why This Matters:**
Knowing which sessions are active helps an actor decide whether to act immediately or wait.

---

### 🚩 Flag 8: Runtime Application Inventory

**Objective:**
Detect the enumeration of running applications and services to inform risk and opportunity.

**Flag Value:**
`tasklist.exe`
`2025-10-09T12:51:57.6866149Z`

**Detection Strategy:**
Hunting for events that capture broad processes, process-list snapshots, or qqueries of running services.

**KQLQuery:**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any ("tasklist", "Get-Process", "Get-Service", "sc query", "wmic process list", "wmic service list")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId, InitiatingProcessParentId, InitiatingProcessUniqueId
| order by TimeGenerated asc
```

**Evidence:**
<img width="2101" height="356" alt="image" src="https://github.com/user-attachments/assets/bcf64b94-6433-4292-8b0a-1b712b853fb9" />

**Why This Matters:**
A process inventory shows what is present and what to avoid or target for collection. As an attacker, understanding what processes are running can simultaneously assist with highlighting valuable targets and processes to obfuscate behind.

---

### 🚩 Flag 9: Privilege Surface Check

**Objective:**
Detect attempts to understand privileges available to the current actor.

**Flag Value:**
`2025-10-09T12:52:14.3135459Z`

**Detection Strategy:**
Searching for any telemetry for any queries related to group memberships, token properties, or priviledge listings.

**KQLQuery:**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any ("whoami", "net user", "net localgroup", "Get-LocalUser", "Get-LocalGroupMember")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId, InitiatingProcessParentId, InitiatingProcessUniqueId
| order by TimeGenerated asc
```

**Evidence:**
<img width="2088" height="362" alt="image" src="https://github.com/user-attachments/assets/79263ede-90c7-4be5-8b7b-b55df3338e26" />

**Why This Matters:**
Priviledge mapping informs whether the actor proceeds as a user or seeks evaluation.

---

### 🚩 Flag 10: Proof-of-Access & Egress Validation

**Objective:**
Find actions that both validate outbound reachability and attempt to capture host state for exfiltration value.

**Flag Value:**
`www.msftconnecttest.com`
`2025-10-09T12:55:15.736717Z`

**Detection Strategy:**
Look for combined evidence of outbound network checks and artifacts created as proof the actor can view or collect host data. Using the timeframe of first execution as the starting point of the query and the remainder of the day as the end, searching for any network events that has both outbound and host queries will narrow down the results. Using the results, the suspicious outbound destinations can be noted.

**KQLQuery:**
```kql
let VMName = "gab-intern-vm";
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-10-09T12:22:27.6514901Z) .. datetime(2025-10-10))
| where DeviceName == VMName
| where AdditionalFields has_all ("Out", "host")
| project TimeGenerated, ActionType, AdditionalFields, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFolderPath,LocalIPType, RemoteIP, Timestamp
| order by TimeGenerated asc
```

**Evidence:**
<img width="2080" height="212" alt="image" src="https://github.com/user-attachments/assets/12824336-1ca0-4b4b-ab1b-007c02dfebc1" />

**Why This Matters:**
The outbound destination `www.msftconnecttest.com` was contacted first. This step demonstrates both access and the potential to move meaningful data off the host.

---

### 🚩 Flag 11: Bundling / Staging Artifacts

**Objective:**
Detect consolidation of artifacts into a single location or package for transfer.

**Flag Value:**
`C:\Users\Public\ReconArtifacts.zip`
`2025-10-09T12:59:05.6804726Z`

**Detection Strategy:**
Search for file system events or operations that show grouping, consolidation, or packaging of gathered items.

**KQLQuery:**
```kql
let VMName = "gab-intern-vm";
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-09T12:22:27.6514901Z) .. datetime(2025-10-15))
| where DeviceName == VMName
| where FileName endswith ".zip"
| project TimeGenerated, ActionType, FileName, FileSize, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath,InitiatingProcessParentFileName,PreviousFileName
| order by TimeGenerated asc
```

**Evidence:**
<img width="1348" height="314" alt="image" src="https://github.com/user-attachments/assets/46693303-02b5-45eb-b196-0dfb41699aca" />

**Why This Matters:**
Staging is the practical step that simplifies exfiltration and should be correlated back to prior recon.

---

### 🚩 Flag 12: Outbound Transfer Attempt (Simulated)

**Objective:**
Identify attempts to move data off-host or test upload capability.

**Flag Value:**
`100.29.147.161`
`2025-10-09T13:00:40.7259181Z`

**Detection Strategy:**
Investigate network events or process activity indicating outbound transfers or upload attempts, even if they fail.

**KQLQuery:**
```kql
let VMName = "gab-intern-vm";
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-10-09T12:22:27.6514901Z) .. datetime(2025-10-10))
| where DeviceName == VMName
| where AdditionalFields has_any ("Out")
| where ActionType contains "SslConnectionInspected"
| project TimeGenerated, RemoteIP, ActionType, AdditionalFields, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by RemoteIP asc
```

**Evidence:**
<img width="2082" height="586" alt="image" src="https://github.com/user-attachments/assets/7b30d32a-455d-4453-bb6d-dab70e071231" />

**Why This Matters:**
Any outbound transfer attempts, regardless of sucess or failure, are clear indications of intent of egress and exfiltration.

---

### 🚩 Flag 13: Scheduled Re-Execution Persistence

**Objective:**
Detect creation of mechanisms that ensure the actor’s tooling runs again on reuse or sign-in.

**Flag Value:**
`SupportToolUpdater`
`2025-10-09T13:01:28.7700443Z`

**Detection Strategy:**
Process or scheduler-related events that create recurring or logon-triggered executions tied to the same actor pattern.

**KQLQuery:**
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-10-9) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any ("schtasks", "Register-ScheduledTask", "New-ScheduledTaskTrigger", "Set-ScheduledTask", "Unregister-ScheduledTask")
| sort by Timestamp asc
```

**Evidence:**
<img width="2082" height="587" alt="image" src="https://github.com/user-attachments/assets/c4aa3efc-c10c-43d1-bd06-3fb4b4db556d" />

**Why This Matters:**
Re-execution mechanisms are the actor’s way of surviving beyond a single session — interrupting them reduces risk.

---

### 🚩 Flag 14: Autorun Fallback Persistence

**Objective:**
Spot lightweight autorun entries placed as backup persistence in user scope.

**Flag Value:**
`RemoteAssistUpdater`

**Detection Strategy:**
Detect registry or startup-area modifications that reference familiar execution patterns or repeat previously observed commands.

**KQLQuery:**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-9) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where RegistryValueData has_any ("Remote")
| sort by TimeGenerated asc
```

**Evidence:**
<img width="1840" height="214" alt="image" src="https://github.com/user-attachments/assets/2dddb962-a166-401a-833e-6bd867886df5" />

**Why This Matters:**
Redundant persistence increases resilience. Finding the fallback to prevent easy re-entry help reduce the possibility of future compromise.

---

### 🚩 Flag 15: Planted Narrative / Cover Artifact

**Objective:**
Identify a narrative or explanatory artifact intended to justify the activity.

**Flag Value:**
`SupportChat_log.lnk`
`2025-10-09T13:02:41.5698148Z`

**Detection Strategy:**
Creation of explanatory files or user-facing artifacts near the time of suspicious operations; focus on timing and correlation rather than contents.

**KQLQuery:**
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-09T12:22:27.6514901Z) .. datetime(2025-10-10))
| where DeviceName == "gab-intern-vm"
| where ActionType in ("FileCreated","FileModified","FileCopied")
| project TimeGenerated, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Evidence:**
<img width="1524" height="313" alt="image" src="https://github.com/user-attachments/assets/e3b43855-ebf0-4319-9478-78dd9b99b8d5" />

**Why This Matters:**
A planted explanation is a classic misdirection. The sequence and context reveal deception more than the text itself. The file `SupportChat_log.lnk` was opened after the mass created fake files.

---

## 🎯 MITRE ATT&CK Technique Mapping

| Flag | Description | MITRE ATT&CK Technique(s) |
|------|-------------|---------------------------|
| **0** | Initial execution from Downloads (SupportTool.ps1) | T1059.001 PowerShell, T1204.002 User Execution, T1036 Masquerading |
| **1** | Defense tamper attempt / staged tamper artifact | T1562.001 Impair Defenses, T1036 Masquerading |
| **2** | Quick data probe (clipboard check) | T1115 Clipboard Data |
| **3** | Host & user context recon | T1082 System Information Discovery, T1033 User Discovery |
| **4** | Storage surface mapping | T1083 File and Directory Discovery, T1135 Network Share Discovery |
| **5** | Connectivity & DNS resolution checks | T1046 Network Service Scanning, T1018 Remote System Discovery, T1071.001 Web Protocol |
| **6** | Interactive session discovery | T1087 Account Discovery, T1033 User Discovery, T1057 Process Discovery |
| **7** | Runtime process inventory | T1057 Process Discovery, T1007 System Service Discovery |
| **8** | Privilege surface check (whoami / groups) | T1069 Permission Groups Discovery, T1033 User Discovery |
| **9** | Proof-of-access + egress validation (outbound + screenshot) | T1113 Screen Capture, T1071.001 Web Protocol |
| **10** | Data staging (ZIP archive) | T1560.001 Archive Collected Data, T1074 Data Staged |
| **11** | Outbound exfiltration test | T1041 Exfil Over C2 Channel, T1567 Exfil to Cloud Storage, T1071.001 Web Protocol |
| **12** | Scheduled task persistence | T1053.005 Scheduled Task / Job |
| **13** | Autorun registry fallback persistence | T1547.001 Registry Run Keys / Startup Folder |
| **14** | Planted narrative / cover artifact (fake logs) | T1036 Masquerading, T1553 Subvert Trust Controls, T1204 User Execution |
| **15** | Final deception artifact (SupportChat_log.lnk) | T1036 Masquerading, T1204.002 User Execution (shortcut), T1553 Subvert Trust Controls |

---

## 🧾 Conclusion
The sequence of events observed across Flags 0–15 forms a coherent and highly structured intrusion chain designed to mimic legitimate support activity while conducting reconnaissance, staging, exfiltration testing, and persistence. The attacker’s workflow followed a logical, methodical progression, beginning with the execution of a suspicious script disguised as SupportTool.ps1 and expanding outward into system, user, network, and privilege reconnaissance.

Each step built cleanly upon the previous one: after probing security controls, the operator quickly checked for opportunistic data such as clipboard contents, then broadened into full host context collection, storage enumeration, and verification of outbound connectivity. This culminated in checks of active sessions and runtime processes—classic pre-operation situational awareness techniques.

With sufficient understanding of the environment, the attacker assessed privilege boundaries and then executed proof-of-access actions, including outbound reachability tests and the capture of host artifacts. These were subsequently staged into an archive, and exfiltration paths were tested through HTTP activity.

Persistence techniques followed immediately afterward: first through scheduled re-execution mechanisms, then via a backup Run-key entry—demonstrating the attacker’s intent to maintain access even if one persistence mechanism was removed.

Finally, the operation concluded with an attempt at narrative shaping. A helpdesk-themed file was planted and even opened, creating a “Recent Items” artifact designed to justify the suspicious activity as routine support interaction. This is a well-known deception tactic meant to deflect scrutiny during post-incident review.

Taken together, the chain illustrates a disciplined adversary moving from initial execution to full operational capability while maintaining a veneer of legitimacy. The defender’s job in such cases is not only to detect each stage, but to recognize the holistic pattern—the unmistakable unfolding of an attack lifecycle behind the facade of IT assistance.

---

## 🎓 Lessons Learned

### 1. Social Engineering Can Masquerade as IT Support

The attacker relied heavily on legitimacy mimicry — naming files “SupportTool.ps1,” placing fake “helpdesk logs,” and generating shortcuts that appeared in Recent Items.

Lesson: Any tool claiming to be support-related should be treated with suspicion unless verified through a trusted deployment channel.

### 2. Early Indicators Are Often Small and Easily Missed

The first malicious action occurred when a script in the Downloads directory was executed.

Lesson: Enforce stricter controls around script execution from user-writable paths.
Baseline expected user behavior: most users do not run PowerShell scripts manually.

### 3. Defense Probing Occurs Before Any Real Damage

The adversary tested Defender visibility, attempted tamper simulation, and checked what data was easily reachable (clipboard, session, environment).

Lesson: Monitoring for attempted tampering or reconnaissance is as important as detecting the tampering itself.

### 4. Reconnaissance Was Systematic and Multi-Layered

The attacker moved through:

Host context
Storage
Network reachability
Sessions
Process inventory
Privilege checks

Lesson: Establish alerting for sequences or clusters of recon activity, not just individual events.

### 5. Staging & Exfiltration Tests Occur Before the Real Theft

The operator created archives, tested HTTP outbound paths, and took screenshots.

Lesson: Outbound egress tests from unfamiliar processes should be treated as high-risk signals.

### 6. Persistence Was Redundant

They created:
Scheduled task persistence
Run key registry fallback persistence

Lesson: Defense must identify persistence families, not just individual techniques.

### 7. “Narrative Files” Are an Emerging Tactic

The final step was dropping a helpdesk-themed artifact meant to explain away unusual logs.

Lesson: Analysts must consider that some files may be intentionally planted to mislead investigations.

### 8. Sequencing Tells a Story

The true detection strength came from seeing how each step connected logically into the next.

Lesson: Threat hunting must look at timelines, not isolated events.

---

## 🛠️ Recommendations for Remediation

### 🔒 1. Endpoint Containment
Goal: stop all attacker activity immediately.

Isolate the affected device using EDR or NAC quarantine.
Terminate suspicious PowerShell and command-line processes.
Block outbound connections associated with known indicators (domains, IPs, ports).

### 🧹 2. Remove Persistence Mechanisms
a. Scheduled Tasks

Review tasks created during the incident timeframe.
Remove any unauthorized or suspicious scheduled tasks.
Validate the referenced script or executable no longer exists.

b. Registry Run Keys

Inspect and clean:
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`

Remove entries linked to SupportTool.ps1 or other unknown scripts.

### 🗑️ 3. Delete Malicious Files

Remove all artifacts related to staging or persistence:
SupportTool.ps1
Any ZIP archive created for data staging
Fake “support logs” or deceptive chat transcripts
SupportChat_log.lnk (if not legitimate)

Use EDR to search by:
File hashes
File paths (Downloads, Temp, Recent Items)

### 🔐 4. Credential Reset & Hardening

Since recon included identity and session enumeration:
Reset passwords for the affected user and any accounts active during compromise.
Revoke sign-in refresh tokens.
Enforce MFA for all accounts.

### 🌐 5. Network Hardening

Strengthen outbound restrictions:
Apply strict egress filtering (limit outbound ports/domains).
Enforce proxy usage; block direct-to-internet traffic.
Enable DNS logging and threat-intel filtering.
Detect/block suspicious PowerShell-based HTTP requests.

### 📊 6. Improve Logging & Monitoring

PowerShell Logging
Enable Script Block Logging
Enable Module Logging
Enforce Constrained Language Mode for non-admins
OS Logging

Enable:
Process creation logging (4688)
Command-line parameters
Registry modification auditing
Task Scheduler operational logs

### 🛡️ 7. Hardening of Security Controls

Enforce least privilege (remove unnecessary local admin rights).
Apply tamper protection for Defender/EDR.
Restrict PowerShell usage to approved roles.
Deploy WDAC or AppLocker allowlisting policies.

### 👥 8. User Awareness & Policy Improvements

Because execution originated from Downloads:
Train users to avoid running unsolicited “support” scripts or tools.
Enforce signed/verified IT tools only.
Improve helpdesk procedures to prevent social engineering.

### 🕵️ 9. Lateral Movement Validation

Check for additional compromise indicators:
Review SMB, RDP, and remote execution logs.
Look for unauthorized local admin account creation.
Correlate abnormal logon events across the domain.

### 🧭 10. Enterprise-Wide Sweep

Search the environment for:
Copies of malicious scripts
Scheduled tasks matching the compromises
Identical registry persistence keys
Suspicious outbound HTTP attempts
Treat any secondary device as compromised.

### 📘 11. Post-Incident Improvements

Update incident response playbooks.
Add detection logic for the ATT&CK techniques used.
Patch the affected machine fully.
Document IoCs and incorporate them into threat hunts.
