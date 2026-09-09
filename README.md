# EmberForge: Source Leak

> **Investigator Note:** Hands-on threat hunt analyzing Active Directory lateral movement and initial access telemetry within Microsoft Sentinel (`law-silentcorridor`).

---

## Executive Summary

An Active Directory incident investigation was conducted across three scope hosts (workstation, file server, domain controller). Analysis identified the initial access vector as a suspicious `rundll32.exe` process execution on the user workstation (`EC2AMAZ-B9GHHO6`), loading an unverified DLL (`review.dll`) from a root directory (`D:\`). 

---

## Q01 — Initial Access Vector & Execution Identification

### Core Findings

* **Anomalous Process:** `rundll32.exe`
* **Parent Process:** `explorer.exe` (User Shell)
* **Loaded Binary:** `D:\review.dll`
* **Execution Timestamp:** `2026-01-30 21:27:03 UTC`
* **Target Host:** `EC2AMAZ-B9GHHO6` (Workstation)
* **ATT&CK Mapping:** [T1218.011 - Signed Binary Proxy Execution: Rundll32](https://attack.mitre.org/techniques/T1218/011/)

---

### Technical Analysis & KQL Query

To isolate system-level execution anomalies, telemetry was scoped to the incident window (`2026-01-30 21:00` to `2026-01-31 01:00 UTC`) across the `EmberForge_CL` dataset.

```kusto
EmberForge_CL
| where SystemTime between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 01:00))
| where NewProcessName contains "rundll32.exe"
| sort by SystemTime asc
| project SystemTime, Computer, NewProcessName, CommandLine, ParentProcessName
```

---

### Query Results & Evidence

All 8 rundll32.exe executions identified during the incident window. Red boxes highlight the anomalous execution at row 6 (21:27:03 UTC) showing the suspicious parent process (explorer.exe) and malicious DLL path (D:\review.dll).

![EmberForge Q01 Query Results - All rundll32 Executions](./evidence/q01_rundll32_query_results.png)

The anomalous execution stands out immediately when comparing against the seven baseline executions spawned by svchost.exe. The shift from system service (svchost) to user shell (explorer.exe) as the parent process, combined with the non-standard DLL path (D:\), confirms malicious execution.

---

### Telemetry Breakdown

**Total Executions:** 8  
**Baseline Activity:** 7 executions were spawned by svchost.exe loading legitimate binaries from C:\Windows\System32\.  
**Anomalous Execution:** 1 execution was spawned directly by explorer.exe invoking a DLL from D:\review.dll.

| Metric | Baseline / Expected Behavior | Observed Anomalous Event |
|--------|-----|-----|
| Parent Process | svchost.exe (System Service) | explorer.exe (Interactive User Context) |
| Binary Path | C:\Windows\System32\ | D:\review.dll |
| Risk Level | Low (System Operation) | High (Potential Payload Execution) |



<img width="1663" height="682" alt="Screenshot 2026-09-09 at 4 33 10 PM" src="https://github.com/user-attachments/assets/dbc28d62-94ab-4513-8c56-3c4db35a01a8" />


---

### Threat Hunter Takeaway

This case highlights the importance of baseline validation over initial assumptions. While `rundll32.exe` is a standard Windows utility, tracing the parent-child process relationship and file paths quickly revealed the execution mechanism. The presence of a user-spawned rundll32 loading from a non-standard directory (D:\) is the hallmark of attacker-controlled code execution.

---

### Investigation Roadmap

- [x] Q01: Initial Access Vector & Execution Identification
- [ ] Q02: Parent Process Lineage & Shell Analysis
- [ ] Q03: Payload Artifact Analysis (review.dll hash/metadata)
- [ ] Q04: Lateral Movement Tracing (Workstation → File Server → DC)
- [ ] Q05: Persistence & Privilege Escalation Audit
