# EmberForge: Source Leak 

## Executive Summary

Active Directory attack investigation spanning three hosts (workstation, file server, domain controller). Initial access vector identified as malicious rundll32.exe execution on workstation, loading attacker-controlled DLL from non-standard path. This marks the entry point for subsequent lateral movement and domain compromise.

---
— Q01 Investigation
## Finding

**Malicious Process:** rundll32.exe spawned by explorer.exe  
**DLL Loaded:** review.dll from D:\review.dll  
**Execution Context:** User-level process, not system service  
**Timeline:** 2026-01-30 21:27:03 UTC (early in incident window)  
**Host:** EC2AMAZ-B9GHHO6 (workstation)

---

## Methodology

Queried EmberForge_CL for all rundll32.exe executions during incident window:

```kusto
EmberForge_CL
| where SystemTime between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 01:00))
| where NewProcessName contains "rundll32.exe"
| sort by SystemTime asc
| project SystemTime, Computer, NewProcessName, CommandLine, ParentProcessName
```

**Result:** 8 total executions identified.

**Analysis:** Seven executions spawned by svchost.exe (Windows system service) loading system DLLs from System32. One execution anomalous: spawned by explorer.exe (user shell) loading DLL from D:\, a non-standard path indicating attacker control.

---

## Technical Significance

| Indicator | Normal Behavior | Observed Behavior |
|-----------|---|---|
| Spawner | svchost.exe (system service) | explorer.exe (user process) |
| DLL Location | C:\Windows\System32\ | D:\review.dll |
| Context | System operation | Attacker-controlled execution |

Rundll32 is legitimate Windows utility. When spawned by user-level process loading DLL from user-writable path, indicates code execution mechanism controlled by attacker.

---

## Impact on Active Directory Investigation

This execution is the initial access point. Subsequent analysis should establish:

1. What code was executed within review.dll (shellcode analysis, behavioral telemetry)
2. What credential or privilege escalation followed (process chains, logon events)
3. Lateral movement path to file server and domain controller
4. Persistence mechanisms deployed (scheduled tasks, account creation, backdoors)
5. AD objects modified (AdminSDHolder, group memberships, ACLs)

---

## Next Steps

Q02: Parent process analysis (what spawned explorer.exe)  
Q03: File analysis (review.dll hash, metadata, creation source)  
Q04: Lateral movement timeline (workstation to file server to DC)  
Q05: Persistence and backdoor identification
