# ZENA Healthcare SOC Incident Response  Project

![Status](https://img.shields.io/badge/status-in%20progress-yellow)

> ⚠️ **This is a simulated exercise.** ZENA Healthcare is a fictional
> organization created for training purposes. No real patient data,
> systems, or breach occurred. This project demonstrates SOC analyst
> skills using Microsoft Sentinel, Defender XDR, and MITRE ATT&CK
> methodology in a controlled training environment.

## Scenario

ZENA Healthcare is eleven days into a cyber incident initially assessed
as a portal DDoS attack. It isn't. As Senior SOC Analyst, I triaged 275
alerts, uncovered a hidden credential-compromise intrusion masked behind
the DDoS assumption, and am hunting the kill chain across Microsoft
Sentinel and Defender XDR toward a UK GDPR/ICO-compliant close within
the 72-hour breach notification window.

## My Role

Senior SOC Analyst (simulated) , responsible for alert triage, threat
hunting, incident escalation, and coordinating the response through to
regulatory notification.

## Tools & Frameworks

- Microsoft Sentinel (KQL, custom log ingestion, Data Collection Rules)
- Microsoft Defender XDR
- Microsoft Entra ID (identity investigation)
- MITRE ATT&CK
- ServiceNow
- VirusTotal · AbuseIPDB · ANY.RUN (threat intel enrichment)
- CyberChef (encoded payload decoding)
- UK GDPR / ICO 72-hour breach notification process

## Environment

- **Cloud platform:** Azure (Log Analytics workspace + Sentinel)
- **SIEM:** Microsoft Sentinel
- **ITSM/ticketing:** ServiceNow (dev instance)
- **Threat intel enrichment:** VirusTotal, AbuseIPDB, ANY.RUN

## Progress

| Phase | Status |
|---|---|
| Phase 0 — Tooling & environment setup | ✅ Complete |
| Phase 1 — Business onboarding & regulatory knowledge checks | ✅ Complete |
| Phase 2 — SIEM data validation & alert triage | ✅ Complete |
| Phase 3 — Cloud identity investigation | ✅ Complete |
| Phase 4 — Malware & threat intelligence analysis | ✅ Complete |
| Phase 5 — Threat hunting & MITRE ATT&CK mapping | ⬜ Not started |
| Phase 6 — Confirmed-incident response & ServiceNow | ⬜ Not started |
| Phase 7 — KPI reporting, remediation, lessons learned | ⬜ Not started |

## Key Findings So Far

**Phase 2 Alert Triage**
- Validated the Sentinel feed before triaging: found 277 ingested rows
  against 275 unique Alert IDs, a connector duplication issue
  (`AL-1048`, `AL-1049`), resolved before calculating any metrics.
- Cross-checked the "portal DDoS" theory against source IP data: 22 of
  30 high-request-rate alerts traced to an internal load-testing
  address, confirmed false positive, not an external attack.
- Full triage of the 275-alert backlog produced a 31.3% true-positive
  rate. Within that, distinguished 68 routine/low-severity true
  positives from **18 alerts forming a single, unbroken attack
  narrative** — phishing → credential harvesting → MFA fatigue →
  privilege escalation → lateral movement toward the EPR tier → data
  staging → attempted exfiltration → C2 beaconing.
- Identified a cross-SIEM discrepancy: Sentinel and Splunk disagree on
  whether one outbound transfer to a suspect IP was blocked or allowed
  — flagged as an open item for the threat-hunting phase.
- **Ingestion pipeline troubleshooting:** built a custom log ingestion
  pipeline end-to-end using Azure Data Collection Rules, a service
  principal (App Registration + role-based access), and the Logs
  Ingestion REST API rather than relying on the wizard's file-upload
  path. Along the way, diagnosed and resolved an OAuth client-secret
  mismatch, a workspace-naming mix-up, and, most notably, a case
  where Sentinel's reserved `TimeGenerated` column was found to reflect
  ingestion time rather than true event time, despite a DCR
  transformation intended to correct it (a known inconsistency on
  Analytics-tier custom tables). Resolved by preserving the original
  event timestamp under a separate field (`AlertTimeGenerated`) and
  using it for all chronological analysis instead.

**Phase 3 Cloud Identity Investigation**
- Confirmed the `j.okeefe` account compromise via Entra ID sign-in logs:
  a 9-prompt MFA-fatigue (push-bombing) burst over 36 minutes, followed
  by a successful sign-in "after repeated MFA prompts" from Rotterdam,
  NL-the same night as the account's last legitimate Manchester
  sign-in.
- **Quantified the impossible-travel finding directly in KQL**, using
  `prev()`/`datetime_diff()` to calculate the exact gap between the
  legitimate and compromised sign-ins: **46 minutes** across ~600km-
  physically impossible by any mode of travel, turning a system-flagged
  alert into a mathematically proven finding.
- Independently verified a second, superficially similar "impossible
  travel" flag on `a.shah` and confirmed it as a genuine false
  positive-`RiskState: dismissed`, normal MFA satisfaction, no
  fatigue pattern, no follow-on suspicious activity-rather than
  accepting the prior analyst's handover note at face value.
- Resolved an open question from the handover notes: `SVC-epr-sync`
  (normally a certificate-based, non-interactive automation account)
  showed an anomalous interactive password sign-in from the same
  Rotterdam IP as the `j.okeefe` compromise, immediately followed by an
  unauthorized **Helpdesk Administrator** role grant — clear evidence of
  privilege escalation, ~26 hours after the initial compromise.
- **Cross-account correlation:** the source IP `45.137.21.88` links the
  `j.okeefe` compromise, the `SVC-epr-sync` privilege escalation, *and*
  the `IMG-WS-07` workstation intrusion from Phase 2 confirming one
  coordinated attack campaign, not several unrelated incidents.
- Produced a board-ready Identity Investigation Report (executive
  summary, timeline, risk assessment, affected-user breakdown, and
  recommendations) for the SOC Manager.
- Repeated the same `TimeGenerated`-vs-ingestion-time issue from Phase
  2's pipeline in this table too, resolved the same way, by querying
  the preserved event-time field instead of the reserved column.
- Began an initial MITRE ATT&CK mapping across the Phase 2–3 findings
  (Credential Access, Privilege Escalation, Command and Control,
  Exfiltration) ahead of the formal mapping in Phase 5.

**Phase 4 — Malware & Threat Intelligence Investigation**
- Decoded the encoded PowerShell payload from `IMG-WS-07` (Defender
  alert DE-9001) via CyberChef — Base64 decode followed by a UTF-16LE
  text decode, since PowerShell's `-EncodedCommand` flag always encodes
  UTF-16LE, not plain ASCII.
- The decoded command performs three distinct actions, each named and
  mapped individually rather than summarized as "malicious": downloads
  and executes a second-stage payload from a C2 domain (**T1105**,
  Ingress Tool Transfer), creates a scheduled task `UpdaterSvc` for
  persistence (**T1053.005**), and invokes **Mimikatz** to dump
  credentials from memory (**T1003.001**)-independently corroborated
  by a separate Defender identity alert (LSASS memory access) 70
  minutes later.
- Identified the C2 domain (`sync-update-cdn.net`, resolving to
  `45.137.21.88`) and confirmed genuine command-and-control behaviour by
  cross-referencing **two independent data sources**: network flow logs
  showed 30+ near-identical connections at a consistent **~15-minute
  interval** over 9+ hours (proving automated beaconing, not human
  activity), while the packet capture (Wireshark) surfaced the live
  `GET /a.ps1` HTTP request and its **User-Agent** —
  `ZenaUpd/1.0 (PowerShell)`, a custom string designed to impersonate a
  legitimate internal updater service-a detail the flow-log CSV has no
  field to capture at all.
- **Threat-intel enrichment returned zero detections** on both the
  domain (VirusTotal) and the IP (AbuseIPDB)-documented as an expected
  result for first-use/simulated attacker infrastructure rather than
  evidence of benign intent; confidence in the finding rests on
  first-party evidence (the decode, Defender alerts, and beacon pattern)
  rather than third-party reputation history.
- Flagged a single anomalous 41.2MB outbound transfer to the same C2 IP
  from a second host (`10.10.4.30`)-consistent with the Phase 2
  Sentinel-vs-Splunk exfiltration discrepancy-carried forward as an
  open item for Phase 5's network hunting.
- Produced a Malware Investigation Report (PowerShell Analysis Note)
  covering payload behaviour, C2 identification, beacon cadence, the
  PCAP-only User-Agent evidence, and why both the PCAP and flow logs
  were required together.

## Investigation Timeline

_Full chronological account in [incident-timeline.md](./incident-timeline.md)-being built out phase by phase._

## Alert Triage

Full triage register and methodology in [/evidence](./evidence).

## IOC Register

Full register with source, confidence, and enrichment evidence in
[/evidence/ioc-register.md](./evidence/ioc-register.md).

| IOC Type | Value | Severity | Confidence |
|---|---|---|---|
| Domain | `sync-update-cdn.net` | Critical | High |
| IP | `45.137.21.88` | Critical | High |
| File Hash | `9f2a4c8e1b7d3f6a0c5e9b2d8f4a1c7e3b6d9f0a2c5e8b1d4f7a0c3e6b9d2f5a` | High | Medium |
| URL | `http://sync-update-cdn.net/a.ps1` | Critical | High |
| Scheduled Task | `UpdaterSvc` | High | High |
| User-Agent | `ZenaUpd/1.0 (PowerShell)` | High | High |

## MITRE ATT&CK Mapping

Initial mapping drafted from Phase 2–3 findings; formal kill-chain
mapping to be finalized in Phase 5.

| Finding | Tactic | Technique | ID |
|---|---|---|---|
| MFA push-bombing | Credential Access | MFA Request Generation | T1621 |
| Impossible-travel sign-in | Initial Access | Valid Accounts | T1078 |
| Sign-in via anonymising proxy | Defense Evasion | External Proxy | T1090.002 |
| SVC-epr-sync interactive sign-in | Privilege Escalation | Valid Accounts: Cloud Accounts | T1078.004 |
| Helpdesk Admin role grant | Privilege Escalation | Account Manipulation | T1098.003 |
| Encoded PowerShell on IMG-WS-07 (decoded, confirmed) | Execution | PowerShell | T1059.001 |
| Second-stage payload download (`a.ps1`) | Execution | Ingress Tool Transfer | T1105 |
| `UpdaterSvc` scheduled task | Persistence | Scheduled Task/Job | T1053.005 |
| Mimikatz credential dump | Credential Access | OS Credential Dumping (LSASS) | T1003.001 |
| DCSync against krbtgt (SVC-epr-sync → DC-01) | Credential Access | OS Credential Dumping: DCSync | T1003.006 |
| Beaconing to `sync-update-cdn.net` (confirmed via PCAP + flow logs) | Command and Control | Application Layer Protocol | T1071.001 |
| Attempted 41.2MB outbound transfer | Exfiltration | Exfiltration Over C2 Channel | T1041 |

## KQL Queries

Investigation queries are in [/kql-queries](./kql-queries), each with a
short comment explaining what it was hunting for and why.

## ICO 72-Hour Response

_To be completed in Sprint 3._

## Repo Structure

```
├── README.md
├── incident-timeline.md
├── screenshots/
├── kql-queries/
├── evidence/
└── ico-notification/
```
