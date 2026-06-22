# Splunk Detection Queries

This document contains the SPL detection rules created for the Splunk Enterprise SOC Detection & Incident Response Lab.

The lab uses Splunk Enterprise, Windows Security Logs, Windows System Logs, Sysmon Operational Logs, and Splunk Universal Forwarder to simulate SOC monitoring, alerting, dashboarding, and incident investigation workflows.

---

## Detection Summary

| Detection ID | Detection Name                           | Data Source                              | MITRE ATT&CK                                |
| ------------ | ---------------------------------------- | ---------------------------------------- | ------------------------------------------- |
| SOC-LAB-001  | Multiple Failed Login Attempts           | Windows Security Event ID 4625           | T1110 - Brute Force                         |
| SOC-LAB-002  | Successful Login After Failed Attempts   | Windows Security Event IDs 4624 and 4625 | T1110 - Brute Force, T1078 - Valid Accounts |
| SOC-LAB-003  | PowerShell Execution Monitoring          | Sysmon Event ID 1                        | T1059.001 - PowerShell                      |
| SOC-LAB-004  | Sysmon Process Creation Monitoring       | Sysmon Event ID 1                        | T1059 - Command and Scripting Interpreter   |
| SOC-LAB-005  | New Windows Service Installed            | Windows Event ID 7045                    | T1543.003 - Windows Service                 |
| SOC-LAB-006  | User Added to Local Administrators Group | Windows Security Event ID 4732           | T1098 - Account Manipulation                |

---

# Detection Rules

## SOC-LAB-001 - Multiple Failed Login Attempts

**Purpose:**
Detects accounts with multiple failed login attempts, which may indicate brute-force activity or password guessing.

**MITRE ATT&CK:**
T1110 - Brute Force

```spl
index=soc_lab sourcetype="WinEventLog:Security" EventCode=4625
| where Account_Name!="-" AND Account_Name!="ANONYMOUS LOGON"
| stats count as failed_count by Account_Name Workstation_Name host
| where failed_count >= 3
| sort - failed_count
```

---

## SOC-LAB-002 - Successful Login After Failed Attempts

**Purpose:**
Identifies accounts that had multiple failed login attempts and at least one successful login within the selected time range. This may indicate a possible successful password guessing attempt.

**MITRE ATT&CK:**
T1110 - Brute Force
T1078 - Valid Accounts

```spl
index=soc_lab sourcetype="WinEventLog:Security" (EventCode=4624 OR EventCode=4625)
| where Account_Name!="-" 
  AND Account_Name!="ANONYMOUS LOGON"
  AND NOT like(Account_Name,"%$")
| eval status=case(EventCode=4625,"failure", EventCode=4624,"success")
| stats count(eval(status="failure")) as failed_logins
        count(eval(status="success")) as successful_logins
        values(Logon_Type) as logon_type
        values(Workstation_Name) as workstation
        by Account_Name host
| where failed_logins >= 3 AND successful_logins >= 1
| sort - failed_logins
```

---

## SOC-LAB-003 - PowerShell Execution Monitoring

**Purpose:**
Monitors PowerShell execution using Sysmon Event ID 1. This helps analysts review PowerShell command-line activity, user context, and parent process relationships.

**MITRE ATT&CK:**
T1059.001 - PowerShell

```spl
index=soc_lab (source="*Sysmon*" OR sourcetype="*Sysmon*") ("powershell.exe" OR "pwsh.exe" OR "PowerShell")
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| rex field=_raw "<Data Name=['\"]Image['\"]>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name=['\"]CommandLine['\"]>(?<CommandLine>[^<]*)</Data>"
| rex field=_raw "<Data Name=['\"]ParentImage['\"]>(?<ParentImage>[^<]*)</Data>"
| rex field=_raw "<Data Name=['\"]User['\"]>(?<User>[^<]*)</Data>"
| search EventCode=1
| where like(lower(Image), "%powershell.exe%") 
   OR like(lower(Image), "%pwsh.exe%") 
   OR like(lower(CommandLine), "%powershell%")
| table _time host EventCode User Image CommandLine ParentImage source sourcetype
| sort - _time
```

---

## SOC-LAB-004 - Sysmon Process Creation Monitoring

**Purpose:**
Uses Sysmon Event ID 1 to monitor selected process creation activity such as `notepad.exe`, `cmd.exe`, and `powershell.exe`. This helps review command-line execution and parent-child process relationships.

**MITRE ATT&CK:**
T1059 - Command and Scripting Interpreter

```spl
index=soc_lab (source="*Sysmon*" OR sourcetype="*Sysmon*")
| rex field=_raw "<EventID>(?<SysmonEventID>\d+)</EventID>"
| rex field=_raw "<Data Name=['\"]Image['\"]>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name=['\"]CommandLine['\"]>(?<CommandLine>[^<]*)</Data>"
| rex field=_raw "<Data Name=['\"]ParentImage['\"]>(?<ParentImage>[^<]*)</Data>"
| rex field=_raw "<Data Name=['\"]User['\"]>(?<User>[^<]*)</Data>"
| search SysmonEventID=1
| eval process=lower(Image)
| where like(process,"%\\notepad.exe") 
   OR like(process,"%\\cmd.exe") 
   OR like(process,"%\\powershell.exe")
| table _time host SysmonEventID User Image CommandLine ParentImage source sourcetype
| sort - _time
```

---

## SOC-LAB-005 - New Windows Service Installed

**Purpose:**
Detects new Windows service installation. This may indicate legitimate software installation, but it can also be used by attackers for persistence.

**MITRE ATT&CK:**
T1543.003 - Windows Service

```spl
index=soc_lab EventCode=7045
| table _time host Service_Name Service_File_Name Account_Name source sourcetype
| sort - _time
```

---

## SOC-LAB-006 - User Added to Local Administrators Group

**Purpose:**
Detects when a user is added to a local security group such as Administrators. This may indicate privilege escalation or unauthorized account permission changes.

**MITRE ATT&CK:**
T1098 - Account Manipulation

```spl
index=soc_lab sourcetype="WinEventLog:Security" EventCode=4732
| table _time host Account_Name Group_Name Member_Name EventCode source sourcetype
| sort - _time
```

---

# Project Summary

This project demonstrates a practical SOC monitoring lab using Splunk Enterprise, Windows Event Logs, Sysmon, and Splunk Universal Forwarder.

The detections cover authentication monitoring, brute-force detection, successful login after failed attempts, PowerShell execution monitoring, Sysmon process creation monitoring, Windows service installation, and local administrator group changes.

The project also includes scheduled alerts, triggered alert validation, SOC dashboard panels, MITRE ATT&CK mapping, and a sample incident report.
