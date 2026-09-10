# SkillProof Warranty — money behind the manifest

SSL certificates won by putting money behind trust (warranties up to $1M+). No agent-skill verifier does this. We will.

## The promise
If a tool holding a valid SkillProof **PASS** manifest is exploited through an **in-scope invariant** inside its **validity window**, SkillProof pays the warranty.

## Coverage tiers
| Tier | Warranty add-on | Max payout | Window |
|---|---|---|---|
| Standard Warranty | +$500 on a Standard verification ($1,500) | $15,000 (10x fee) | 90 days |
| Fleet Warranty | +$5,000 on a fleet tier | $150,000 | 180 days |
| Continuous Warranty | included in Continuous ($300/skill/mo) while subscribed | $15,000 per incident | rolling |

## What is covered
- Exploitation of an invariant that was **verified held** in the manifest (e.g., SSRF guard verified held, then bypassed in the pinned version).
- The exact **pinned version + code hash**. A version bump voids coverage until re-verified (this sells Continuous).

## What is NOT covered
- Invariants marked `not_held` or notes in the manifest (buyer was warned).
- Out-of-scope systems named in the manifest.
- Buyer misconfiguration, credential leaks, or social engineering.
- Modified, re-bundled, or unpinned deployments.

## Claims process
1. Buyer submits reproducer + impact statement within 14 days of discovery.
2. SkillProof re-runs the battery against the pinned version within 7 days.
3. If the battery confirms the invariant broke: payout within 30 days.
4. Every paid claim is published (anonymized) — claims make the product stronger.

## Funding
- 20% of every verification fee goes into a segregated warranty reserve.
- Reserve balance published quarterly. If reserve < 2x max outstanding exposure, warranty sales pause.
- Reinsurance once annual verification revenue crosses $500k.

## Why this is the unignorable move
- It converts our methodology into a **financial guarantee** competitors can't match without doing the work.
- It forces us to be excellent: every payout is a public methodology failure we must fix.
- It gives enterprise buyers the one thing scanners never offer: someone to bill when they're wrong.

## Launch rule
Warranty goes live after the **first $25k of verification revenue** — the reserve must exist before the promise does.
