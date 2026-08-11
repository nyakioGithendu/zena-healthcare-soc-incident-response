# ZENA Healthcare SOC Incident Response — Simulation Project

![Status](https://img.shields.io/badge/status-in%20progress-yellow)

> **Simulation.** ZENA Healthcare 
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

Senior SOC Analyst (simulated) — responsible for alert triage, threat
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
| Phase 3 — Cloud identity investigation | 🔄 In progress |
| Phase 4 — Malware & threat intelligence analysis | ⬜ Not started |
| Phase 5 — Threat hunting & MITRE ATT&CK mapping | ⬜ Not started |
| Phase 6 — Confirmed-incident response & ServiceNow | ⬜ Not started |
| Phase 7 — KPI reporting, remediation, lessons learned | ⬜ Not started |

## Key Findings So Far

**Phase 2 — Alert Triage**
- Validated the Sentinel feed before triaging: found 277 ingested rows
  against 275 unique Alert IDs — a connector duplication issue, resolved
  before calculating any metrics.
- Cross-checked the "portal DDoS" theory against source IP data: 22 of
  30 high-request-rate alerts traced to an internal load-testing
  address — confirmed false positive, not an external attack.
- Full triage of the 275-alert backlog produced a 31.3% true-positive
  rate. Within that, distinguished 68 routine/low-severity true
  positives from **18 alerts forming a single, unbroken attack
  narrative** — phishing → credential harvesting → MFA fatigue →
  privilege escalation → lateral movement toward the EPR tier → data
  staging → attempted exfiltration → C2 beaconing.
- Identified a cross-SIEM discrepancy: Sentinel and Splunk disagree on
  whether one outbound transfer to a suspect IP was blocked or allowed
  — flagged as an open item for the threat-hunting phase.

**Phase 3 — Identity Investigation (in progress)**
- Investigating the `j.okeefe` account compromise via Entra ID sign-in
  logs: an MFA-fatigue pattern followed by an impossible-travel sign-in.
- Quantifying the exact time gap between the two sign-ins to prove the
  travel was physically impossible, rather than relying on the
  system's flag alone.
- Distinguishing this genuine compromise from a second, superficially
  similar "impossible travel" flag on a different account — verifying
  independently rather than taking the prior analyst's handover note at
  face value.
- Investigating an anomalous privilege grant on a service account
  (`SVC-epr-sync`) for a possible link to the same compromise.

## Investigation Timeline

_Full chronological account in [incident-timeline.md](./incident-timeline.md) — being built out phase by phase._

## Alert Triage

Full triage register and methodology in [/evidence](./evidence).

## MITRE ATT&CK Mapping

_To be completed as the kill chain is confirmed in later phases._

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
