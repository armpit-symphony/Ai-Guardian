# Recommended First Pilot Profiles

Choosing the right first pilot user is critical. The goal is to get real usage signal without business risk, and to find someone who will give honest, detailed feedback.

---

## Ideal First Pilot Profile

### Primary Recommendation: Internal DevOps / Platform Team

**Profile:**
- Runs 1–3 AI agents that perform infrastructure tasks (file ops, code execution, API calls)
- Has a genuine need for governance (executives or security team asking questions about agent behavior)
- Technical enough to read API docs and work through issues independently
- Willing to give honest feedback
- NOT under extreme time pressure

**Why this works:**
- Safe sandbox — agents that make mistakes don't break production (or breaks are recoverable)
- Real governance need — they're already worried about "what is my agent actually doing?"
- Technically capable — won't get stuck on basic auth/API issues
- Business risk: LOW — DevOps mistakes are usually recoverable

**Success indicators:**
- Reads docs thoroughly (they'll actually use the onboarding guide)
- Willing to run the full checklist (they understand why it matters)
- Gives structured feedback (they understand the value of the governance layer)

---

### Alternative Profile B: Internal AI R&D Team

**Profile:**
- Building or evaluating AI agents for future product use
- Currently operating agents in dev/staging without governance
- Wants to understand what governance looks like before going production
- Research-oriented — interested in the problem space

**Why this works:**
- Low pressure — they're evaluating, not betting production on it
- Feedback quality tends to be high — they're analyzing, not just using
- You get early signal on what's confusing before it's in front of business users

**Risk:** Business risk LOW, but may not surface operational friction from real production workflows.

---

### Alternative Profile C: External Partner (MVP Partner)

**Profile:**
- Company with a genuine need for AI governance (regulated industry, security-conscious)
- Wants early access to the product in exchange for detailed feedback
- Has technical staff who can integrate and test
- Willing to sign a pilot agreement (feedback in exchange for free/discounted access)

**Why this works:**
- Highest quality feedback signal — they're paying attention
- Real business context — actual governance needs, not test scenarios
- Potential to convert to paying customer

**Risk:** Requires NDAs, pilot agreements, and more management overhead. Best as second or third pilot.

---

## Anti-Patterns to Avoid

### ❌ Production-Critical Agent as First Pilot
**Profile:** Running Ai-Guardian in front of an agent that handles real money, customer data, or security operations.

**Why avoid:** Any false positive (safe action blocked) or governance hiccup could cause real business harm. You'll also be more conservative in testing edge cases.

**When to use:** Only after you've established baseline confidence through safer pilots.

---

### ❌ Non-Technical Business User as First Pilot
**Profile:** Someone who will primarily interact with a dashboard, not APIs.

**Why avoid:** They'll surface UI/UX issues, which are valid but not the priority for a governance-first pilot. They also may not catch the nuanced behaviors (SSRF protection, breakglass semantics) that need testing.

**When to use:** After the governance layer is proven, when building the operator dashboard (Phase 2).

---

### ❌ Builder/Contributor as Own Pilot User
**Profile:** Someone who helped build Ai-Guardian testing it.

**Why avoid:** They'll skip reading docs ("I wrote it, I know how it works"), skip steps because they know the shortcuts, and won't surface documentation friction. Zero discovery value.

**When to use:** Internal builders should always test in an adversarial capacity — trying to break, not use.

---

### ❌ Multiple Teams Simultaneously as First Pilot
**Profile:** Three different teams all trying Ai-Guardian at the same time.

**Why avoid:** Feedback will be inconsistent, you'll get conflicting signals, and support overhead triples. No clear ownership of "this is working."

**When to use:** Only after you've refined the onboarding based on pilot 1's feedback.

---

## Recommended Pilot Sequence

| Pilot | Profile | Duration | Focus |
|---|---|---|---|
| **Pilot 1** | Internal DevOps/Platform (safe workload) | 2 weeks | All core workflows, docs quality, setup friction |
| **Pilot 2** | Internal AI R&D (real workload, non-critical) | 2 weeks | Production-like usage, feedback quality, approval workflow |
| **Pilot 3** | External MVP partner (actual business need) | 3–4 weeks | Full signal, real stakes, conversion potential |

---

## Before Approaching a Pilot User

**Confirm:**
- [ ] You have deployment-ready code (not just features in flight)
- [ ] You can commit to responding to pilot feedback within 48 hours
- [ ] You have a clear escalation path if something breaks
- [ ] Someone on the team "owns" this pilot relationship (not just whoever is free)
- [ ] Pilot user understands this is a pilot (not a finished product)

**Prepare:**
- Share `docs/pilot/README.md` and `PILOT_ONBOARDING.md` before they start
- Give them a single point of contact for questions
- Set expectations on response time (48h for non-critical, same-day for security issues)

---

## Recommended First Pilot Selection Criteria

| Criterion | Weight | Notes |
|---|---|---|
| Technical capability (can read API docs) | Required | Can't be the limiting factor |
| Real governance need exists | Required | They should want this, not just be doing you a favor |
| Workload is recoverable if something goes wrong | Required | Non-production or dev environment |
| Willingness to give detailed feedback | High | Ask them directly: "Will you fill out the feedback form?" |
| No extreme time pressure | Medium | Stressed teams don't give good feedback |
| Potential to expand to production | Bonus | Nice to have, not required |
