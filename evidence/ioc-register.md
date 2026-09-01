# Phase 4 — IOC Register

> **Note on timestamps:** all times referenced are UTC unless otherwise stated.

Source data: `zena_defender_endpoint_alerts.csv`, `zena_defender_identity_alerts.csv`,
`zena_network_logs.csv`, `zena_network_capture.pcap`

---

| IOC Type | IOC Value | Severity | Source | Confidence | MITRE Technique | Notes / Context |
|---|---|---|---|---|---|---|
| Domain | `sync-update-cdn.net` | Critical | CyberChef decode; Defender (DE-9002); Network logs | High | T1071.001 | C2 domain called by the decoded PowerShell's `DownloadString`. Confirmed as beacon destination — 30+ connections at ~15-minute intervals over 9+ hours. VirusTotal: 0 detections (expected for simulated/first-use infrastructure). |
| IP | `45.137.21.88` | Critical | Defender (DE-9001, DE-9002); Entra ID sign-in logs (Phase 3 — `j.okeefe` impossible-travel sign-in); Network logs; Wireshark | High | T1071.001 | Resolved IP for the C2 domain. Same IP links the `j.okeefe` and `SVC-epr-sync` compromises (Phase 3) to this workstation intrusion — confirms one coordinated campaign. AbuseIPDB: 0% confidence score, no prior reports (expected for simulated/first-use infrastructure). |
| File Hash (SHA256) | `9f2a4c8e1b7d3f6a0c5e9b2d8f4a1c7e3b6d9f0a2c5e8b1d4f7a0c3e6b9d2f5a` | High | Defender (DE-9001, FileHash_SHA256) | Medium | T1059.001 | Hash of the malicious PowerShell process on IMG-WS-07. Confidence Medium — sourced from Defender only, not yet independently corroborated by a second file-reputation source. |
| URL | `http://sync-update-cdn.net/a.ps1` | Critical | Wireshark (GET request observed directly in packet capture, `http.request and ip.addr == 45.137.21.88`); corroborated by CyberChef decode | High | T1105 | Second-stage payload URL. Present in the decoded PowerShell text and independently confirmed as an actual HTTP request in the PCAP — two-source corroboration. |
| Scheduled Task | `UpdaterSvc` | High | Defender (DE-9003) | High | T1053.005 | Persistence mechanism — re-runs encoded PowerShell every 5 minutes. Created 02:20, 25 minutes after initial execution (01:55) — timing rules out a coincidental legitimate task name. |
| Tool | Mimikatz (`Invoke-Mimikatz -DumpCreds`) | High | CyberChef decode; Defender (DE-9004); Defender identity alert DI-3001 (LSASS memory access, 03:05) | High | T1003.001 | Named directly in the decoded command. Independently corroborated by a separate identity-layer LSASS access alert 70 minutes later. |
| User-Agent | `ZenaUpd/1.0 (PowerShell)` | High | Wireshark (HTTP request headers, PCAP-only — not present in flow log CSV) | High | T1105 / T1071.001 | Custom, non-browser user-agent designed to impersonate a legitimate internal updater service. The `(PowerShell)` component confirms scripted origin, not human browsing. Only observable via packet capture. |

---

## Enrichment Results

**VirusTotal — `sync-update-cdn.net`**
0/90 security vendors flagged the domain. Consistent with newly-registered or first-use attacker infrastructure — absence of detections reflects absence of prior reporting, not evidence of benign intent.

**AbuseIPDB — `45.137.21.88`**
0% abuse confidence score, no prior reports. Same interpretation as above — confidence in this IOC's malicious nature rests on first-party evidence (decoded payload, Defender alerts, beacon pattern, cross-account correlation), not third-party reputation history.

---

## Related Open Item

A single anomalous 41.2MB outbound transfer to `45.137.21.88` was identified in the network logs, originating from a second host (`10.10.4.30`) rather than `IMG-WS-07` itself. This is consistent with the Phase 2 finding of a Sentinel-vs-Splunk discrepancy over whether an outbound transfer was blocked or allowed. Carried forward as an open item for Phase 5 network hunting.
