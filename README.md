# ZENA Healthcare SOC Incident Response — Simulation Project

> ⚠️ **This is a simulated exercise.** ZENA Healthcare is a fictional
> organization created for training purposes. No real patient data,
> systems, or breach occurred. This project demonstrates SOC analyst
> skills using Microsoft Sentinel, Defender XDR, and MITRE ATT&CK
> methodology in a controlled training environment.

## Scenario

ZENA Healthcare is eleven days into a cyber incident initially assessed
as a portal DDoS attack. It isn't. As Senior SOC Analyst, I triaged 275
alerts, uncovered a hidden credential-compromise intrusion masked behind
the DDoS assumption, hunted the kill chain across Microsoft Sentinel and
Defender XDR, and drove the incident to a UK GDPR/ICO-compliant close
within the 72-hour breach notification window.

## My Role

Senior SOC Analyst (simulated) — responsible for alert triage, threat
hunting, incident escalation, and coordinating the response through to
regulatory notification.

## Tools & Frameworks

- Microsoft Sentinel
- KQL (Kusto Query Language)
- Microsoft Defender XDR
- MITRE ATT&CK
- ServiceNow
- UK GDPR / ICO 72-hour breach notification process

## Environment

- **Cloud platform:** Azure (Log Analytics workspace + Sentinel)
- **SIEM:** Microsoft Sentinel
- **ITSM/ticketing:** ServiceNow (dev instance)
- **Threat intel enrichment:** VirusTotal, AbuseIPDB, ANY.RUN

## Investigation Timeline

_To be completed as the investigation progresses — see [incident-timeline.md](./incident-timeline.md) for the full chronological account._

| Day | Event |
|-----|-------|
| Day 1–11 | Incident initially triaged as DDoS on customer portal |
| TBD | ... |

## Alert Triage

_Summary of the 275-alert queue: how it was prioritised, what was
dismissed as noise, and what surfaced as signal. Full detail in
[/evidence](./evidence)._

## Key Findings

_To be completed — the pivot point where the DDoS assumption breaks down
and the credential-compromise intrusion is uncovered._

## MITRE ATT&CK Mapping

_To be completed — tactics and techniques identified during the hunt,
mapped to the kill chain._

| Tactic | Technique | Evidence |
|--------|-----------|----------|
| TBD | TBD | TBD |

## KQL Queries

Hunting and detection queries used during the investigation are in
[/kql-queries](./kql-queries), each with a short comment explaining what
it was hunting for and why.

## ICO 72-Hour Response

_To be completed — the breach assessment, decision log, and (redacted)
notification drafted to meet the ICO's 72-hour requirement under UK
GDPR._

## Repo Structure

```
├── README.md
├── incident-timeline.md
├── screenshots/
├── kql-queries/
├── evidence/
└── ico-notification/
```
