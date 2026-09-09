# EmberForge: Source Leak — Threat Hunt Report

> **Hunter Note:** Digging into an Active Directory lab scenario inside Microsoft Sentinel (`law-silentcorridor`). This write-up covers my process for tracking down the initial access point across our scope hosts.

---

## Executive Summary

An Active Directory incident investigation was conducted across three scoped hosts (workstation, file server, domain controller). Analysis identified the initial access vector as a suspicious `rundll32.exe` process execution on the user workstation (`EC2AMAZ-B9GHHO6`), loading an unverified DLL (`review.dll`) from a root directory (`D:\`).

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

Out of 8 total rundll32.exe executions identified during the incident window, 7 followed normal system baselines while 1 stood out immediately. The red boxes in the screenshot below highlight the anomalous execution at row 6 (21:27:03 UTC) — notice the parent process shift from svchost.exe to explorer.exe, and the DLL loading from D:\ instead of System32.

![EmberForge Q01 Query Results - All rundll32 Executions](./evidence/q01_rundll32_query_results.png)

---

### Telemetry Breakdown

| Metric | Baseline / Expected Behavior | Observed Anomalous Event |
|--------|-----|-----|
| Parent Process | svchost.exe (System Service) | explorer.exe (Interactive User Context) |
| Binary Path | C:\Windows\System32\ | D:\review.dll |
| Risk Level | Low (Normal System Operation) | High (Potential Malicious Payload) |

**Baseline Activity (7 events):** Spawned by svchost.exe loading legitimate system binaries from C:\Windows\System32\.

**Anomalous Event (1 event):** Spawned directly by explorer.exe at 21:27:03 UTC, executing a DLL straight from D:\review.dll.

---

### Threat Hunter Takeaway

This was a great example of why establishing a solid baseline matters. rundll32.exe runs all the time in Windows, but once you filter out the noise and look at the parent process and file path, the anomaly jumps right off the screen. A user-level process (explorer.exe) spawning rundll32 to load a DLL from a non-standard path (D:\) is textbook attacker behavior. The mistake they made was simple: they didn't hide where they put the payload.

---

### Investigation Roadmap

- [x] Q01: Initial Access Vector & Execution Identification
- [ ] Q02: Parent Process Lineage & Shell Analysis
- [ ] Q03: Payload Artifact Analysis (review.dll hash/metadata)
- [ ] Q04: Lateral Movement Tracing (Workstation → File Server → DC)
- [ ] Q05: Persistence & Privilege Escalation Audit
