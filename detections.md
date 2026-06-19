# Splunk Detection Queries

## Multiple Failed Login Attempts

**MITRE ATT&CK:** T1110 – Brute Force

```spl
index=soc_lab sourcetype="WinEventLog:Security" EventCode=4625
| where Account_Name!="-" AND Account_Name!="ANONYMOUS LOGON"
| stats count as failed_count by Account_Name Workstation_Name host
| where failed_count >= 3
| sort - failed_count
```

---

## Successful Login After Multiple Failed Attempts

**MITRE ATT&CK:** T1110 – Brute Force, T1078 – Valid Accounts

```spl
index=soc_lab sourcetype="WinEventLog:Security" (EventCode=4624 OR EventCode=4625)
| eval status=if(EventCode=4624,"success","failure")
| stats count(eval(status="failure")) as failed_logins count(eval(status="success")) as successful_logins by Account_Name host
| where failed_logins >= 3 AND successful_logins >= 1
```

---

## Suspicious Process Execution Monitoring

**MITRE ATT&CK:** T1059.001 – PowerShell

```spl
index=soc_lab source="*Sysmon*" powershell
| rex "<EventID>(?<SysmonEventID>\d+)</EventID>"
| search SysmonEventID=1
```

## Project Summary

This project demonstrates the implementation of a SOC monitoring lab using Splunk Enterprise, Windows Event Logs, Sysmon, and Splunk Universal Forwarder. The detections focus on brute-force activity, suspicious authentication patterns, and PowerShell-based process execution monitoring.

```
```
