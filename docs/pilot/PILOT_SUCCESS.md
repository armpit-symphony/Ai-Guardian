# Pilot Success Criteria

These are the measurable criteria for determining whether an Ai-Guardian pilot is successful.

---

## Category A: Deployment Readiness

| # | Criterion | Target | How to Measure |
|---|---|---|---|
| A1 | Deployment completed without builder assistance | 100% of setup steps completed by pilot team alone | Pilot team signs off on checklist |
| A2 | Time from bootstrap to first monitored action | < 30 minutes | Timestamps from pilot checklist |
| A3 | Pilot team can create keys for new roles without help | All roles (admin/ingest/viewer) tested | Pilot checklist sign-off |
| A4 | TLS proxy configured correctly | External endpoints use HTTPS | `curl -I` shows valid TLS |
| A5 | Backup verified working | At least one successful backup restore test | Restore test documented |

**Threshold:** All A1–A5 must pass for pilot to proceed to workflow testing.

---

## Category B: Operator Independence

| # | Criterion | Target | How to Measure |
|---|---|---|---|
| B1 | Operator can complete full workflow using only docs | Zero builder interventions during core workflow test | Builder watches but does not help |
| B2 | No clarification questions during pilot checklist run | ≤ 2 clarifying questions total | Builder logs questions |
| B3 | Operator can find and interpret blocked action responses | 100% of blocked scenarios explained correctly | Quiz during debrief |
| B4 | Operator understands breakglass is one-time use | 100% understanding | Quiz during debrief |
| B5 | Operator can use audit log to answer "what happened?" | Correctly identifies events from audit | Exercise during debrief |

**Threshold:** B1–B5 target: ≥ 90% pass rate. Any "blocker" rating (5/5 friction) on core workflows triggers review.

---

## Category C: Core Workflow Validation

| # | Criterion | Target | How to Measure |
|---|---|---|---|
| C1 | Safe action (`read_logs`) returns `allowed` on first try | 100% | Automated or manual test |
| C2 | High-risk action enters pending queue correctly | 100% | `execute_code` test |
| C3 | Admin can approve pending action and agent sees result | 100% | End-to-end test |
| C4 | Admin can deny pending action correctly | 100% | End-to-end test |
| C5 | Blocked action returns `blocked` with clear reason | 100% | `delete_all_files` test |
| C6 | SSRF internal URL blocked with correct reason | 100% | SSRF test cases |
| C7 | Breakglass creates → uses → audited correctly | 100% | Breakglass test |
| C8 | Audit log contains all expected events | 100% | Compare audit vs. known events |
| C9 | Audit hash chain validates after all operations | 100% | `GET /audit/verify` returns `valid: true` |

**Threshold:** All C1–C9 must pass.

---

## Category D: Feedback & Usability

| # | Criterion | Target | How to Measure |
|---|---|---|---|
| D1 | Pilot feedback form completed | 100% | Submitted feedback template |
| D2 | No critical (blocker-level) friction reported | 0 critical blockers | Feedback form Section 3/4 |
| D3 | Operator independence score | ≥ 3.5/5 | Feedback form Section 2 |
| D4 | Documentation quality average | ≥ 3/5 | Feedback form Section 8 |
| D5 | Recommendation likelihood | ≥ 4/10 (Would recommend) | NPS-style question Section 9 |

**Threshold:** D1–D5 must meet targets. Feedback informs Phase 2 improvements, not pilot pass/fail.

---

## Category E: Security Regression

| # | Criterion | Target | How to Measure |
|---|---|---|---|
| E1 | No critical action was allowed without proper approval/breakglass | 0 violations | Audit log review |
| E2 | Audit hash chain integrity maintained throughout pilot | 100% valid | `GET /audit/verify` throughout |
| E3 | Auth failures behave correctly (401, not 500) | 100% correct errors | Auth tests |
| E4 | Breakglass PIN not guessed/brute-forced | 0 failed attempts before legitimate use | Audit log |
| E5 | No data loss or corruption | 0 incidents | Service uptime + DB integrity |

**Threshold:** Any E1–E5 failure is a **hard stop** — escalate to deployment team immediately.

---

## Scoring Summary

| Category | Weight | Pass Threshold |
|---|---|---|
| A: Deployment Readiness | 20% | 5/5 items |
| B: Operator Independence | 20% | ≥ 90% items |
| C: Core Workflow Validation | 30% | 9/9 items |
| D: Feedback & Usability | 10% | 5/5 targets met |
| E: Security Regression | 20% | 0 violations |

**Overall Pilot Score:** Weighted average  
**Pass grade:** ≥ 75% overall with ZERO security regressions (E1–E5 all green)

---

## Pilot Outcomes

### 🟢 PASS — Ready for Expansion
- Overall ≥ 75%, all E items green
- Proceed to: wider team rollout, production consideration

### 🟡 CONDITIONAL PASS — Minor Issues
- Overall ≥ 60%, E items green
- Address friction items (D scores) before expansion
- Schedule follow-up review in 2 weeks

### 🔴 PARTIAL — Significant Issues Found
- Overall < 60% OR any E item failed
- Do not expand pilot
- Schedule remediation session
- Re-run pilot checklist after fixes

### 🛑 FAIL — Blocker Found
- Any E1–E5 critical failure
- Immediate escalation to deployment team
- Full security review before any further piloting

---

## Pilot Duration & Checkpoints

| Phase | Duration | Milestone |
|---|---|---|
| Setup & Bootstrap | Day 1 | All A items complete |
| Core Workflows | Day 1–2 | All C items complete |
| Ongoing Monitoring | Day 2–14 | Collect D feedback |
| Security Review | Day 14 | E items validated |
| Final Assessment | Day 14 | Scoring + recommendation |

**Minimum pilot duration:** 2 weeks of real agent activity  
**Maximum pilot duration:** 4 weeks (after which a go/no-go decision is required)
