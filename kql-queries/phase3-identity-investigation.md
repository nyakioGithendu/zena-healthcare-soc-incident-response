# Phase 3 — Cloud Identity Investigation: KQL Investigation Library

> **Note on timestamps:** all times below are UTC unless otherwise stated.

Table queried: `SigninLogs_CL_CL` (Entra ID sign-in logs, ZENA Healthcare workspace)

---

## 1. Feed Validation: Row Count

```kql
SigninLogs_CL_CL
| count
```
**Investigates:** Confirms the total number of sign-in records successfully ingested, before any analysis is trusted.

**Result:** 209 rows — matches the source file exactly.

---

## 2. Feed Validation: Duplicate Detection

```kql
SigninLogs_CL_CL
| summarize Occurrences = count() by SigninID
| where Occurrences > 1
```
**Investigates:** Checks whether any SigninID appears more than once, indicating a connector or ingestion duplication issue — the same class of problem identified in Phase 2's Sentinel alert feed.

**Result:** Two duplicate IDs confirmed (`SI-50021`, `SI-50022`). Neither is tied to j.okeefe, a.shah, or SVC-epr-sync, so they don't affect the compromise findings but are documented as a data-quality observation.

---

## 3. Feed Validation: Time Range Coverage

```kql
SigninLogs_CL_CL
| summarize EarliestSignIn = min(SignInTimeGenerated), LatestSignIn = max(SignInTimeGenerated)
```
**Investigates:** Confirms ingested timestamps reflect genuine event times (not ingestion time) and span the expected incident window.

**Result:** 05/06/2026 03:00 – 12/06/2026 19:36. Note: Sentinel's reserved `TimeGenerated` column was found to reflect ingestion time rather than true event time — a known inconsistency on Analytics-tier custom tables, also encountered in Phase 2. Resolved by using the preserved `SignInTimeGenerated` field for all chronological analysis.

---

## 4. j.okeefe: Full Sign-In Sequence

```kql
SigninLogs_CL_CL
| where UserPrincipalName == "j.okeefe@zena.health"
| project SignInTimeGenerated, ResultType, ResultDescription, IPAddress, Location, RiskState
| sort by SignInTimeGenerated asc
```
**Investigates:** Reconstructs every sign-in attempt (success and failure) for the clinical administrator account under investigation, in chronological order.

**Result (18 rows):** A consistent daily Manchester sign-in pattern (5–9 June, all Success, RiskState none), followed at 21:55 on 9 June by the last legitimate Manchester sign-in, then a burst of MFA-denial failures from Rotterdam, NL (`45.137.21.88`, RiskState `atRisk`) beginning at 22:03 — the full shape of an account takeover.

---

## 5. j.okeefe: MFA Fatigue Burst Isolated

```kql
SigninLogs_CL_CL
| where UserPrincipalName == "j.okeefe@zena.health"
| where SignInTimeGenerated between (datetime(2026-06-09T21:30:00Z) .. datetime(2026-06-10T03:00:00Z))
| project SignInTimeGenerated, ResultType, ResultDescription, IPAddress, Location
| sort by SignInTimeGenerated asc
```
**Investigates:** Narrows the timeline to the specific incident window to isolate the MFA push-bombing pattern.

**Result (13 rows):** Nine consecutive MFA denials between 22:03 and 22:39 (36 minutes) from the same Rotterdam IP, immediately followed by a success at 22:41 logged as "Success after repeated MFA prompts."

---

## 6. Quantifying the Impossible Travel

```kql
SigninLogs_CL_CL
| where UserPrincipalName == "j.okeefe@zena.health" and ResultType == "0"
| project SignInTimeGenerated, Location, IPAddress
| sort by SignInTimeGenerated asc
| serialize
| extend PrevTime = prev(SignInTimeGenerated), PrevLocation = prev(Location)
| extend GapMinutes = datetime_diff('minute', SignInTimeGenerated, PrevTime)
| project SignInTimeGenerated, Location, PrevLocation, PrevTime, GapMinutes
```
**Investigates:** Calculates the exact elapsed time between consecutive successful sign-ins, testing whether the location change is physically feasible.

**Result:** A **46-minute** gap between the legitimate Manchester sign-in (09/06 21:55) and the compromised Rotterdam sign-in (09/06 22:41). Manchester to Rotterdam is approximately 600km — physically impossible to travel in 46 minutes by any means. This converts "impossible travel" from a system-generated label into a mathematically proven finding.

---

## 7. a.shah: Full Sign-In Sequence

```kql
SigninLogs_CL_CL
| where UserPrincipalName == "a.shah@zena.health"
| project SignInTimeGenerated, IPAddress, Location, RiskState, ConditionalAccessStatus, ResultDescription
| sort by SignInTimeGenerated asc
```
**Investigates:** Applies the same scrutiny given to j.okeefe to a second account flagged for a foreign sign-in, to determine independently whether it represents a genuine threat.

**Result (12 rows):** A single Malaga, Spain sign-in on 08/06 at 09:30 against an otherwise entirely UK-based pattern (Birmingham, Manchester, Leeds, London), with `RiskState: dismissed` on that one entry and normal MFA satisfaction throughout. No burst of failures, no anomalous follow-on activity.

---

## 8. SVC-epr-sync: Full Sign-In and Role History

```kql
SigninLogs_CL_CL
| where UserPrincipalName == "SVC-epr-sync@zena.health"
| project SignInTimeGenerated, AppDisplayName, AuthMethod, IPAddress, Location, RiskState, ResultDescription
| sort by SignInTimeGenerated asc
```
**Investigates:** Reviews the service account's authentication history to resolve the open question of how and when it was granted Helpdesk Administrator privileges.

**Result (8 rows):** Six consecutive days (5–10 June) of expected non-interactive, certificate-based sign-ins from internal IP `10.10.4.9`, abruptly interrupted on 11 June at 01:08 by an interactive, password-based sign-in from `45.137.21.88` (Rotterdam) — flagged as "anomalous for service account" — followed four minutes later at 01:12 by the Helpdesk Administrator role assignment from the same IP.

---

## 9. Cross-Account Correlation

```kql
SigninLogs_CL_CL
| where IPAddress == "45.137.21.88"
| project SignInTimeGenerated, UserPrincipalName, AppDisplayName, ResultDescription, RiskState
| sort by SignInTimeGenerated asc
```
**Investigates:** Identifies every account touched by the specific IP address already linked to malicious activity on the IMG-WS-07 workstation in Phase 2, testing whether the identity compromise and the endpoint compromise are connected.

**Result (14 rows):** `45.137.21.88` appears across the j.okeefe MFA-fatigue/takeover sequence and, separately, the SVC-epr-sync interactive sign-in and role escalation — proving this is a single coordinated attack campaign using shared infrastructure, not two unrelated incidents. This is the finding that ties Phase 2 and Phase 3 together into one coherent kill chain.
