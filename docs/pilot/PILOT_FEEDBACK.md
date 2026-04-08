# Pilot Feedback Template

**Pilot participant:** _________________________  
**Date:** _________________________  
**Ai-Guardian version:** _________________________  
**Deployment type:** ☐ Self-hosted ☐ Managed ☐ Other: ________

---

## Section 1: Setup Experience

### How long did initial setup take?
- ☐ < 15 minutes
- ☐ 15–30 minutes
- ☐ 30–60 minutes
- ☐ > 1 hour

### Setup friction (rate each):
1 = No friction, 5 = Major blocker

| Task | Rating | Notes |
|---|---|---|
| Bootstrap tenant | ☐1 ☐2 ☐3 ☐4 ☐5 | |
| Create API keys | ☐1 ☐2 ☐3 ☐4 ☐5 | |
| Register agent | ☐1 ☐2 ☐3 ☐4 ☐5 | |
| TLS/proxy setup | ☐1 ☐2 ☐3 ☐4 ☐5 | N/A ☐ |
| Backup configuration | ☐1 ☐2 ☐3 ☐4 ☐5 | N/A ☐ |

### What was hardest about setup?
_______________________________________________

### What would have made setup easier?
_______________________________________________

---

## Section 2: Core Workflows

### Approval queue workflow
Rate each step (1 = Easy, 5 = Confusing/blocker):

| Step | Rating | Notes |
|---|---|---|
| Submitting an action | ☐1 ☐2 ☐3 ☐4 ☐5 | |
| Discovering a pending approval | ☐1 ☐2 ☐3 ☐4 ☐5 | |
| Understanding what action was requested | ☐1 ☐2 ☐3 ☐4 ☐5 | |
| Approving a pending action | ☐1 ☐2 ☐3 ☐4 ☐5 | |
| Denying a pending action | ☐1 ☐2 ☐3 ☐4 ☐5 | |
| Knowing when my agent can retry | ☐1 ☐2 ☐3 ☐4 ☐5 | |

### What was confusing about the approval flow?
_______________________________________________

### How long does the approve/deny decision typically take you?
- ☐ < 1 minute
- ☐ 1–5 minutes
- ☐ 5–15 minutes
- ☐ > 15 minutes

---

## Section 3: Blocked Actions

### Did blocked actions make sense when you saw them?
- ☐ Always clear why it was blocked
- ☐ Usually clear
- ☐ Sometimes confusing
- ☐ Often unclear

### Rate the blocked action response:
1 = Very clear, 5 = Completely unclear

| Field | Rating |
|---|---|
| `decision` field meaning | ☐1 ☐2 ☐3 ☐4 ☐5 |
| `reason` field helpfulness | ☐1 ☐2 ☐3 ☐4 ☐5 |
| `risk_score` helpfulness | ☐1 ☐2 ☐3 ☐4 ☐5 |
| Time to understand what to do | ☐1 ☐2 ☐3 ☐4 ☐5 |

### False positives (safe actions that were blocked):
List any actions that were blocked but you believe should have been allowed:
_______________________________________________

---

## Section 4: SSRF Protection

### Did you encounter any SSRF blocks?
- ☐ No
- ☐ Yes — describe below

If yes:
- What action/context triggered it?
- Was it a false positive (legitimate external URL blocked)?
- Was it a true positive (internal URL correctly blocked)?

_______________________________________________

### Rate the SSRF error messages:
1 = Very clear, 5 = Completely unclear

| Aspect | Rating |
|---|---|
| Clarity of why URL was blocked | ☐1 ☐2 ☐3 ☐4 ☐5 |
| Knowing what URL caused the block | ☐1 ☐2 ☐3 ☐4 ☐5 |

---

## Section 5: Breakglass

### Have you used breakglass?
- ☐ No, haven't needed to
- ☐ Yes, in a real emergency
- ☐ Yes, in testing (pilot checklist)

### If used: Rate the breakglass experience:
1 = Very smooth, 5 = Major blocker

| Step | Rating | Notes |
|---|---|---|
| Finding/obtaining the PIN | ☐1 ☐2 ☐3 ☐4 ☐5 | |
| Creating a breakglass session | ☐1 ☐2 ☐3 ☐4 ☐5 | |
| Using the breakglass to override | ☐1 ☐2 ☐3 ☐4 ☐5 | |
| Understanding it was one-time only | ☐1 ☐2 ☐3 ☐4 ☐5 | |
| Confirm parameter requirement | ☐1 ☐2 ☐3 ☐4 ☐5 | |

### PIN rotation: Did you rotate the PIN during the pilot?
- ☐ No
- ☐ Yes — how did it go? ________________________________

---

## Section 6: Audit Log

### How useful is the audit log for your work?
- ☐ Essential — I check it regularly
- ☐ Somewhat useful
- ☐ Rarely needed
- ☐ Not useful at all

### Rate each audit feature:

| Feature | Rating | Notes |
|---|---|---|
| Viewing recent events | ☐1 ☐2 ☐3 ☐4 ☐5 | |
| Filtering by decision type | ☐1 ☐2 ☐3 ☐4 ☐5 | |
| The `/blocked` shortcut | ☐1 ☐2 ☐3 ☐4 ☐5 | |
| Hash chain verification | ☐1 ☐2 ☐3 ☐4 ☐5 | |
| Understanding action attribution (who did what) | ☐1 ☐2 ☐3 ☐4 ☐5 | |

### What would make the audit log more useful?
_______________________________________________

---

## Section 7: Visibility & Observability

### What do you wish you could see that you currently can't?
1. _______________________________________________
2. _______________________________________________
3. _______________________________________________

### Did the `GET /api/v1/status` endpoint meet your needs?
- ☐ Yes
- ☐ Partially — what's missing? ________________________________
- ☐ I haven't used it

---

## Section 8: Documentation Quality

Rate each document (1 = Useless, 5 = Perfect):

| Document | Rating |
|---|---|
| PILOT_ONBOARDING.md | ☐1 ☐2 ☐3 ☐4 ☐5 |
| QUICKSTART.md | ☐1 ☐2 ☐3 ☐4 ☐5 |
| API.md | ☐1 ☐2 ☐3 ☐4 ☐5 |
| BREAKGLASS_RUNBOOK.md | ☐1 ☐2 ☐3 ☐4 ☐5 |
| PILOT_CHECKLIST.md | ☐1 ☐2 ☐3 ☐4 ☐5 |
| PILOT_SUPPORT.md | ☐1 ☐2 ☐3 ☐4 ☐5 |

### What docs are missing that you needed?
_______________________________________________

---

## Section 9: Overall

### Would you recommend Ai-Guardian to another team?
- ☐ Yes, without hesitation
- ☐ Yes, with reservations
- ☐ Maybe
- ☐ No

### What is the single biggest pain point?
_______________________________________________

### What is the single best thing about Ai-Guardian?
_______________________________________________

### What would have to change for you to go to production with this?
_______________________________________________

---

## Section 10: Workload Fit

### What type of agent workload are you running?
- ☐ Data processing / ETL
- ☐ Code generation / review
- ☐ File operations
- ☐ External API calls
- ☐ Research / summarization
- ☐ Other: ________________________________

### How many agents will ultimately use this?
- ☐ 1–5
- ☐ 5–20
- ☐ 20–100
- ☐ 100+

### What actions do your agents perform most?
1. _______________________________________________
2. _______________________________________________
3. _______________________________________________

---

**Thank you for your feedback!**  
Submit to: your-deployment-team@pilotcompany.com  
Deadline for pilot feedback: _______________
