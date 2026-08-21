# ZENA Healthcare Incident  MITRE ATT&CK Mapping

> **Status:** Initial mapping, compiled from confirmed Phase 2 (Alert Triage) and Phase 3 (Identity Investigation) findings. Formal validation and any additional techniques from endpoint/network hunting will be added in Phase 5.
>
> **Note on timestamps:** all times referenced are UTC unless otherwise stated.

## Purpose

This document maps every confirmed finding from the ZENA Healthcare investigation to the MITRE ATT&CK framework, so the incident can be understood not just as a list of alerts, but as a coherent adversary campaign — what the attacker did, in what order, and why each step mattered.

---

## Kill Chain Overview

The confirmed timeline spans two attack surfaces — an endpoint (`IMG-WS-07`) and two identities (`j.okeefe`, `SVC-epr-sync`) — tied together by a single piece of shared attacker infrastructure: **source IP `45.137.21.88`**. This shared IP is the strongest evidence that this is one coordinated campaign, not several unrelated incidents.

```
Phishing email → Credential harvesting → MFA-fatigue attack → Account takeover (j.okeefe)
        ↓                                                              ↓
Encoded PowerShell (IMG-WS-07)                          EPR access + anonymised proxy use
        ↓                                                              ↓
LSASS credential access                          SVC-epr-sync interactive sign-in (same C2 IP)
        ↓                                                              ↓
Persistence (scheduled task)                     Helpdesk Administrator role self-assigned
        ↓
Lateral movement toward EPR tier
        ↓
Data staged to archive → Attempted exfiltration → C2 beaconing
```

---

## Technique Mapping

| # | Finding | Source | Tactic | Technique | ID |
|---|---|---|---|---|---|
| 1 | Phishing email reported by user, part of the confirmed 18-alert kill chain narrative | Phase 2 | Initial Access | Phishing | T1566 |
| 2 | MFA-fatigue / push-bombing: 9 consecutive denied prompts over 36 minutes against j.okeefe, followed by one mistaken approval | Phase 3 | Credential Access | Multi-Factor Authentication Request Generation | T1621 |
| 3 | Successful sign-in from Rotterdam, NL, 46 minutes after a legitimate Manchester sign-in — quantified as physically impossible | Phase 3 | Initial Access | Valid Accounts | T1078 |
| 4 | Sign-in routed through an anonymising proxy after initial compromise | Phase 3 | Defense Evasion | Proxy: External Proxy | T1090.002 |
| 5 | Encoded (Base64/UTF-16) PowerShell command executed on IMG-WS-07 | Phase 2 | Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| 6 | LSASS memory access observed on IMG-WS-07 | Phase 2 | Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 |
| 7 | Scheduled task created on IMG-WS-07, timing consistent with the malicious PowerShell activity | Phase 2 | Persistence | Scheduled Task/Job | T1053 |
| 8 | SVC-epr-sync — normally certificate-based, non-interactive — showed an anomalous interactive password sign-in from the same C2 IP as j.okeefe's compromise | Phase 3 | Privilege Escalation / Defense Evasion | Valid Accounts: Cloud Accounts | T1078.004 |
| 9 | Helpdesk Administrator role assigned to SVC-epr-sync four minutes after the anomalous sign-in, from the same IP | Phase 3 | Privilege Escalation | Account Manipulation: Additional Cloud Roles | T1098.003 |
| 10 | Movement toward EPR application tier and large-volume EPR record query, part of the confirmed kill chain | Phase 2 | Lateral Movement / Collection | Remote Services / Data from Information Repositories | T1021 / T1213 |
| 11 | Data staged to an archive file ahead of transfer | Phase 2 | Collection | Data Staged | T1074 |
| 12 | Attempted outbound transfer to `45.137.21.88`, disputed between Sentinel ("blocked") and Splunk ("allowed") — unresolved discrepancy | Phase 2 | Exfiltration | Exfiltration Over C2 Channel | T1041 |
| 13 | Beaconing traffic to `45.137.21.88` at regular intervals, consistent with automated C2 rather than human browsing | Phase 2 | Command and Control | Application Layer Protocol | T1071 |

---

## Cross-Referenced Evidence — Why This Is One Campaign, Not Several

The single strongest piece of evidence in this investigation is that **source IP `45.137.21.88` appears in three independently-discovered findings**:

1. Network/beaconing traffic from `IMG-WS-07` (Phase 2)
2. The compromised sign-in and subsequent EPR/portal access for `j.okeefe` (Phase 3)
3. The anomalous interactive sign-in and privilege escalation for `SVC-epr-sync` (Phase 3)

Each of these was identified separately, using different log sources (Defender/network logs, and two different Entra ID account investigations) , the correlation was not assumed, it was discovered by cross-referencing IP addresses across independently-triaged findings. This is what elevates the incident from "an endpoint alert and two account alerts" to "one attacker, one campaign, three footholds."

---

## Open Items for Phase 5 (Formal Threat Hunting)

- Confirm the initial access vector into `IMG-WS-07` ,is it linked to the phishing alert in the Phase 2 kill chain, or a separate entry point?
- Resolve the Sentinel-vs-Splunk discrepancy on whether the outbound transfer was actually blocked.
- Determine whether any data confirmed left the network, and if so, what was exfiltrated (relevant to EPR/PACS record scope).
- Confirm whether Helix Imaging (PACS supplier) activity is connected to the same campaign (per their inbound query, ticket `INC0010051`).
- Validate technique confidence levels against additional endpoint/network evidence once Defender and network capture data are fully hunted.
