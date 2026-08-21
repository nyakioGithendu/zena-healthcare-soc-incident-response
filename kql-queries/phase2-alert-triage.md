# Phase 2 — SIEM Data Validation & Alert Triage: KQL Investigation Library

> **Note on timestamps:** all times below are UTC unless otherwise stated.

Table queried: `SentinelAlerts_v2_CL_CL` (Sentinel alert export, ZENA Healthcare workspace)

---

## 1. Feed Validation: Row Count

```kql
SentinelAlerts_v2_CL_CL
| count
```
**Investigates:** Confirms the total number of alert records successfully ingested, before any triage or metrics are trusted.

**Result:** 554 rows (double-ingested during pipeline troubleshooting — see notes below).

---

## 2. Deduplication to Clean Dataset

```kql
SentinelAlerts_v2_CL_CL
| where isnotempty(AlertTimeGenerated)
| summarize arg_max(AlertTimeGenerated, *) by AlertID
```
**Investigates:** Collapses the feed to one row per AlertID, keeping the most recent version of each, to establish a clean working dataset.

**Result:** 275 unique alerts — consistent with the original CSV-level finding (277 raw rows, 275 unique IDs).

---

## 3. Duplicate AlertID Detection (Original Data-Quality Finding)

```kql
SentinelAlerts_v2_CL_CL
| where isnotempty(AlertTimeGenerated)
| summarize Occurrences = count() by AlertID
| where Occurrences > 1
```
**Investigates:** Identifies which specific AlertIDs were duplicated in the source feed — a genuine upstream ingestion artifact, separate from the pipeline-troubleshooting duplication noted above.

**Result:** Two duplicate AlertIDs confirmed: `AL-1048`, `AL-1049`. One of the two duplicate pairs also carried an inconsistent `ConfidenceScore` value between copies — a further sign of a flaky source connector.

---

## 4. Time Range Validation

```kql
SentinelAlerts_v2_CL_CL
| where isnotempty(AlertTimeGenerated)
| summarize EarliestAlert = min(AlertTimeGenerated), LatestAlert = max(AlertTimeGenerated)
```
**Investigates:** Confirms ingested timestamps reflect genuine alert/event time rather than ingestion time, and span the expected incident window.

**Result:** Real June 2026 dates spanning the incident window, confirmed after resolving a `TimeGenerated`-vs-ingestion-time collision (documented in the README) by using the preserved `AlertTimeGenerated` field.

---

## 5. Alert-Type Pivot

```kql
SentinelAlerts_v2_CL_CL
| where isnotempty(AlertTimeGenerated)
| summarize arg_max(AlertTimeGenerated, *) by AlertID
| summarize Count = count() by AlertRule
| sort by Count desc
```
**Investigates:** Breaks down the 275-alert backlog by rule type, to prioritize triage effort and see where alert volume actually concentrates before assuming any one theory (e.g., "portal DDoS") is correct.

**Result:** "High request rate to Patient Portal" (30 alerts) was the largest single category — the cluster underpinning the board's DDoS assumption, examined directly in Query 6 below.

---

## 6. Portal Cluster Drill-Down — Testing the DDoS Theory

```kql
SentinelAlerts_v2_CL_CL
| where isnotempty(AlertTimeGenerated)
| summarize arg_max(AlertTimeGenerated, *) by AlertID
| where AlertRule == "High request rate to Patient Portal"
| summarize Count = count() by SourceIP
```
**Investigates:** Breaks down the "portal DDoS" alert cluster by source IP, to test — rather than assume — whether the traffic originates externally (a real attack) or internally (a false positive).

**Result:** 22 of 30 alerts trace to `10.20.5.44`, an internal RFC1918 address confirmed as ZENA's internal load-testing infrastructure. The remaining 8 alerts share the same rule name but different systems/entities, indicating a rule-tagging inconsistency rather than a coordinated second wave. **Verdict: False Positive — the "portal DDoS" was internal load-testing traffic, not an attack.**

---

## Summary — Triage Outcome

Full triage of the deduplicated 275-alert backlog produced a **31.3% true-positive rate**. Within the true positives, 68 alerts were routine/low-severity findings already handled by existing controls, while **18 alerts formed a single, unbroken attack narrative**: phishing → credential harvesting → MFA fatigue → privilege escalation → lateral movement toward the EPR tier → data staging → attempted exfiltration → C2 beaconing. This kill chain is the real incident hiding beneath the dismissed portal noise, and is the thread picked up and confirmed with identity evidence in Phase 3.
