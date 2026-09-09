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


<img width="1663" height="682" alt="Screenshot 2026-09-09 at 4 33 10 PM" src="https://github.com/user-attachments/assets/768186af-8973-4207-9b68-f88cff47e76c" />


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

## Q02 — Where It Actually Came From

### Core Findings

* **Downloaded Archive:** `EmberForge_Review.7z`
* **Archive Contents:** `EmberForge_Review.iso`
* **ISO Mount Point:** `D:\`
* **Payload Location:** `D:\review.dll`
* **Delivery Method:** Self-extracting 7z → ISO → Virtual Drive Mount
* **ATT&CK Mapping:** [T1566.001 - Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)

---

### Technical Analysis & KQL Query

User `lmartin` downloaded `EmberForge_Review.7z` via Microsoft Edge at approximately 21:20 UTC. The archive was extracted to `C:\Users\lmartin.EMBERFORGE\Downloads\EmberForge_Review\` at 21:24:04 UTC using 7-Zip GUI.

The extracted contents included `EmberForge_Review.iso`, which was subsequently mounted as a virtual drive (`D:\`). This mounting occurred between 21:24:04 and 21:27:03 UTC — precisely before the malicious rundll32.exe execution loaded `D:\review.dll`.

Tracking file creation and download events for lmartin:

```kusto
EmberForge_CL
| where SystemTime between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 01:00))
| where Computer == "EC2AMAZ-B9GHHO6"
| where TargetFilename has_any ("7z", "iso", "EmberForge")
| sort by SystemTime asc
| project SystemTime, Computer, User, Image, TargetFilename
```

This query reveals the complete chain: 7z installer download → archive extraction → ISO file creation → drive mount sequence.

---

### The ISO-in-Archive Delivery Trick

This is a sophisticated evasion technique:

**Why it works:**
- 7z archives bypass browser Mark-of-the-Web (MOTW) checks on download
- ISO files, when mounted, do not inherit MOTW metadata
- DLLs accessed from mounted virtual drives appear to come from a trusted location (a drive letter), not from Downloads
- Windows Defender and SmartScreen have reduced visibility into mounted ISO contents

**The sequence:**
1. Download `EmberForge_Review.7z` → File sits in Downloads with MOTW flag
2. Extract 7z → `EmberForge_Review.iso` created locally (no MOTW check)
3. Mount ISO as `D:\` → DLL accessed from virtual drive (appears trusted)
4. Load `D:\review.dll` via rundll32 → Executes with minimal EDR friction

---

### Timeline

| Timestamp | Event | Location |
|-----------|-------|----------|
| 21:20 UTC | Download via Edge | C:\Users\lmartin.EMBERFORGE\Downloads\ |
| 21:23 UTC | 7-Zip installer launched | C:\Users\lmartin.EMBERFORGE\Downloads\ |
| 21:24:04 UTC | Archive extracted | EmberForge_Review.iso created |
| 21:27:03 UTC | rundll32 executes D:\review.dll | Malicious payload runs |

---

### Threat Hunter Takeaway

This delivery mechanism highlights why file source and access path matter. A DLL is equally malicious whether it sits on C:\ or D:\, but the path influences detection logic. By nesting the payload inside an ISO inside an archive, the attacker created layers of indirection that slow detection and reduce metadata propagation. The technique is simple but effective — and it's becoming more common in enterprise attacks precisely because it works.

---




