# Cyber Defense: Incident Response & DFIR

A complete incident response investigation against a compromised Azure Windows VM (`corp-na03-ido2`) running an internet-exposed MySQL server and RDP endpoint. The investigation covers dual independent attacks, full kill-chain reconstruction across MySQL audit logs and Defender Advanced Hunting telemetry, DFIR investigation package analysis, and a formal NIST SP 800-61r2 incident report.

_**Inception State:**_ A suspicious host is flagged. No investigation has been performed, no attacker actions are known, and the system is still fully exposed to the internet.

_**Completion State:**_ The full attack chain is reconstructed, a formal incident report is produced, MDE investigation packages are forensically compared pre vs. post, and all eradication and recovery steps are completed.

<img width="1111" height="471" alt="Screenshot 2026-07-19 at 8 39 31 PM" src="https://github.com/user-attachments/assets/c53dde3d-f665-4ae5-9194-6655d2636476" />
<img width="1110" height="628" alt="Screenshot 2026-07-19 at 8 41 52 PM" src="https://github.com/user-attachments/assets/ee41e7cf-43fb-4e46-b852-265a0e9c5900" />
<img width="1111" height="287" alt="Screenshot 2026-07-19 at 8 40 22 PM" src="https://github.com/user-attachments/assets/73864d74-2f58-4bae-9b2f-4f8f5a1a5b49" />

[Attack Map JSON](https://docs.google.com/document/d/1tuy7b_cb9mMjMe6QPwz5Cw1E5vBTdYK0gyaApRtz848/edit?usp=sharing)

---

# Technology Utilized
- **Microsoft Defender for Endpoint** -- Advanced Hunting, Live Response, Investigation Packages
- **Azure Log Analytics / Microsoft Sentinel** -- KQL queries across `DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`, `DeviceRegistryEvents`, `MySQLAudit_CL`
- **Azure Virtual Machines** -- compromised host (`corp-na03-ido2`), Windows 11 Pro
- **MySQL Workbench** -- database forensics and ransom note confirmation
- **PowerShell** -- eradication and hardening scripts

---

# Table of Contents

- [Phase 1 -- MySQL Authentication Log Analysis](#phase-1--mysql-authentication-log-analysis)
- [Phase 2 -- MySQL Query Log Analysis](#phase-2--mysql-query-log-analysis)
- [Phase 3 -- Defender OS Layer Analysis](#phase-3--defender-os-layer-analysis)
- [Phase 4 -- Network Event Analysis](#phase-4--network-event-analysis)
- [Phase 5 -- DFIR Investigation Package Comparison](#phase-5--dfir-investigation-package-comparison)
- [Phase 6 -- Incident Report](#phase-6--incident-report)
- [Phase 7 -- Eradication and Recovery](#phase-7--eradication-and-recovery)
- [Incident Summary](#incident-summary)

---

### Phase 1 -- MySQL Authentication Log Analysis

MySQL authentication logs (`MySQLAudit_CL`) are analyzed to determine whether the database was accessed by an unauthorized actor. A KQL query separates genuine successful logins from the noise of failed authentication attempts, identifies attacker source IPs, and pinpoints the exact moment credentials were compromised.

**Key finding:** `213.209.159.115` conducted a ~460-attempt automated spray over 2.5 hours. The `root` account was cracked at **2026-07-15 02:08 UTC**. The first post-crack query (`SELECT @@max_allowed_packet`) is an automated tool fingerprint, confirming no human was at the keyboard at breach time. Five minutes later, a clean operator IP (`91.217.249.32`) connected in a classic spray-and-pivot pattern.

```kusto
// MySQL auth successes after compromise time
let MyDevice = "corp-na03-ido2";
let MyTimeframe = todatetime("2026-07-14T21:50:37Z");
let FailedConnections =
    MySQLAudit_CL
    | extend RawData = replace_string(RawData, "\t", " ")
    | extend DeviceName = tostring(split(_ResourceId, "/")[-1])
    | where DeviceName == MyDevice
    | where RawData has "Access denied"
    | extend ConnectionId = extract(@"^\S+\s+(\d+)\s+Connect", 1, RawData)
    | distinct ConnectionId;
MySQLAudit_CL
| where TimeGenerated > MyTimeframe
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == MyDevice
| where RawData has "Connect"
| extend ConnectionId = extract(@"^\S+\s+(\d+)\s+Connect", 1, RawData)
| extend ActionType = case(
    RawData has "Access denied", "LogonFailure",
    ConnectionId in (FailedConnections), "Ignore",
    "LogonSuccess")
| where ActionType != "Ignore"
| extend Username = replace_string(tostring(split(tostring(split(RawData,"@")[0])," ")[-1]),"'","")
| extend IpAddress = replace_string(tostring(split(split(RawData,"@")[1]," ")[0]),"'","")
| project TimeGenerated, DeviceName, Username, IpAddress, ActionType, RawData
| order by TimeGenerated desc
```

---

### Phase 2 -- MySQL Query Log Analysis

Query logs are analyzed to reconstruct exactly what the attacker did inside the database after gaining access. The analyst identifies the full kill chain: enumeration, exfiltration via `mysqldump`-style `SQL_NO_CACHE` reads, ransom note injection, database destruction, and a deliberate `REVOKE` command designed to block DBA recovery.

**Key findings:**
- Full table dumps of `credentials`, `customers`, `orders`, and `payments` from `corp_03` -- confirmed data exfiltration
- `CREATE TABLE RECOVER_YOUR_DATA` + `INSERT` of ransom note containing BTC address and contact
- `DROP DATABASE corp_03`, `sakila`, `world`, resulting in the complete destruction of three databases
- `REVOKE INSERT, UPDATE, DELETE, DROP, CREATE ON *.* FROM root@'%'` demonstrating intentional lockout of recovery access

```kusto
// DB destruction and ransom note window
let MyDevice = "corp-na03-ido2";
let ServerVulnerableDateTime = todatetime("2026-07-14T21:50:37Z");
MySQLAudit_CL
| where TimeGenerated > ServerVulnerableDateTime
| where RawData has "Query"
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == MyDevice
| extend Query = split(RawData, "Query")[1]
| where Query has_any ("DROP DATABASE","DROP TABLE","RECOVER_YOUR_DATA","REVOKE","CREATE USER","GRANT ALL")
| project TimeGenerated, DeviceName, ActionType="Query", Query, RawData
| order by TimeGenerated asc
```

---

### Phase 3 -- Defender OS Layer Analysis

In parallel with the MySQL attack, Defender Advanced Hunting telemetry reveals a second, independent attack against the host's exposed RDP port (3389). Multiple automated bots brute-forced the Windows `administrator` account. Three separate source IPs successfully cracked the credential on the same day. This generally indicates the password was in a common wordlist.

**Key findings:**
- `administrator` cracked by `80.66.83.80` at 03:06 Jul 16, then re-cracked by `197.156.112.253` and `187.149.111.178`
- `141.98.80.88` established a **RemoteInteractive** (full RDP desktop) session at 17:05 Jul 16
- Administrator profile did not exist at baseline.Created during attacker session, confirming interactive presence
- Zero malicious processes, file drops, Run keys, or scheduled tasks observed. Attacker had access but did not deploy a payload

```kusto
// RDP brute-force summary by source IP
let MyDevice = "corp-na03-ido2";
DeviceLogonEvents
| where DeviceName == MyDevice
| where AccountName == "administrator"
| summarize
    Failures = countif(ActionType == "LogonFailed"),
    Successes = countif(ActionType == "LogonSuccess"),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by RemoteIP
| order by Failures desc
```

---

### Phase 4 -- Network Event Analysis

`DeviceNetworkEvents` are queried to answer the most critical open question: what did the attacker do on the network during their interactive RDP session? All 57 network events from the administrator session window are cross-referenced against the full attacker IP list.

**Key finding:** All 57 connections used ports 80 or 443 exclusively and resolved to Microsoft or CDN infrastructure. Zero matches to any known attacker IP. No C2 beaconing, no data exfiltration, no tool downloads observed. The session appears to have been GUI exploration. The attacker landed an interactive desktop but did not execute a payload before the collection window closed.

```kusto
let MyDevice = "corp-na03-ido2";
let AttackerIPs = dynamic(["213.209.159.115","91.217.249.32","80.66.83.80",
    "197.156.112.253","187.149.111.178","141.98.80.88","186.10.68.218"]);
let LetFirstSuccessfulLogonTime = todatetime("2026-07-14T23:16:02Z");
DeviceNetworkEvents
| where TimeGenerated >= LetFirstSuccessfulLogonTime
| where DeviceName == MyDevice
| where RemoteIP in (AttackerIPs)
    or InitiatingProcessAccountName =~ "administrator"
| project TimeGenerated, InitiatingProcessAccountName,
    InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by TimeGenerated desc
```

---

### Phase 5 -- DFIR Investigation Package Comparison

Two MDE live-response investigation packages are collected from the same host. One pre-breach (2026-07-14) and one post-breach (2026-07-18), and compared forensically across every standard artifact category: autoruns, services, scheduled tasks, processes, network connections, users/groups, prefetch, and temp directories.

**Methodology:** Each artifact file is diffed programmatically across both packages. Changes are classified as ADDED, REMOVED, CHANGED, or UNCHANGED, then assessed as benign or suspicious.

**Strongest indicators confirmed by package differential:**

| Indicator | Evidence | ATT&CK |
|---|---|---|
| `administrator` profile non-existent at baseline, created Jul 16 | `administrator_TempDirFiles.txt`: path error in pre, files dated 07/16 in post | T1078.003 Local Accounts |
| `RDPCLIP.EXE-6AB36D08.pf` new in post | New RDP clipboard process -- first-ever administrator session | T1021.001 RDP |
| `UNREGMP2.EXE`, `IE4UINIT.EXE` prefetch new in post | First-time Windows user profile setup utilities executed | T1078.003 |
| Ports 3306 and 3389 still listening on `0.0.0.0` | Both attack surfaces remain open 75 hours post-breach | T1595 Active Scanning |
| No persistence artifacts added | No rogue Run keys, tasks, or services | N/A (exculpatory) |

[DFIR Comparison Report](https://docs.google.com/document/d/1xlk_rIsg3Ri_3pJ_2kBLPShrvPwJEbmiy7r3NTcWzcQ/edit?tab=t.lmkq5dxmzy9p)

---

### Phase 6 -- Incident Report

A formal incident report written in accordance with NIST SP 800-61r2, integrating findings from all prior analysis phases into a single coherent deliverable covering the full incident lifecycle.

**Report sections:**
- Executive Summary
- Incident Details (with KQL to populate each field)
- Impact Assessment (confidentiality, integrity, availability, scope, business impact)
- Indicators of Compromise (full IOC table)
- Timeline (chronological, source-cited)
- Root Cause / Attack Vector
- Response Actions (containment, eradication, recovery)
- Evidence / Artifacts Referenced
- Lessons Learned / Recommendations (6 prioritized items)
- Host DFIR Report (package differential -- baseline, verdict, deltas, ATT&CK mapping, gaps)

[Incident Report](https://docs.google.com/document/d/1xlk_rIsg3Ri_3pJ_2kBLPShrvPwJEbmiy7r3NTcWzcQ/edit?usp=sharing)

---

### Phase 7 -- Eradication and Recovery

Following isolation via MDE "Isolate device," eradication and recovery are performed. Because both the VM and MySQL Server were compromised, the recommended path is to destroy the VM and restore the database from a known-good backup. The steps below reflect the alternative approach taken, hardening the existing system in place for environments where destroying the VM is not feasible.

**Eradication and recovery steps completed:**

- [x] Hardened the VM's NSG (restricted TCP/3306 and TCP/3389 from `0.0.0.0` to trusted source IPs only)
- [x] Powered the VM on and removed from MDE isolation
- [x] Ran a full malware scan using Windows Defender
- [x] Enabled the Windows Firewall (`wf.msc`) on all profiles
- [x] Deleted the `administrator` account (no built-in administrator should be present)
- [x] Confirmed the Guest account is disabled
- [x] Set a strong username and password for the local account
- [x] Configured MySQL to disallow remote root login (removed `root@'%'` wildcard-host binding)
- [x] Set a strong password for the `root` account authenticating over the network (or deleted it)
- [x] Restored `corp_03` data from backup

---

### Incident Summary

The host `corp-na03-ido2` sustained two independent, opportunistic attacks over a 25-hour window -- both enabled by internet-exposed services with weak credentials and no lockout policy.

| Layer | Attack | First Success | Outcome |
|---|---|---|---|
| MySQL (port 3306) | Credential spray, `root` | 2026-07-15 02:08 UTC | Exfiltration + database destruction + ransom note |
| Windows OS (port 3389) | RDP brute-force, `administrator` | 2026-07-16 03:06 UTC | Interactive session established; no payload deployed |

**Databases destroyed:** `corp_03` (business), `sakila`, `world`

**Data confirmed exfiltrated:** `credentials` (username, password, role), `customers` (name, email, phone, address), `orders`, `payments` (card_brand, card_masked, card_last4, exp_month)

**Ransom demand:** 0.0131 BTC to `bc1qa83x6l2dlgkx7cc9rmrymscp5sa3ljepu42w2r`

**Vulnerability reduction:** All root-cause conditions (exposed ports, weak credentials, no lockout, no MFA) resolved during eradication.
