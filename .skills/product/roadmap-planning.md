---
name: roadmap-planning
tier: MEDIUM
domains: [roadmap, OKR, prioritization, RICE, now-next-later, outcome-roadmap]
---
## Activation
Load on: roadmap creation, OKR planning, feature prioritization, quarterly planning,
now/next/later, outcome-based roadmap, strategic sequencing.

## Outcome Roadmap (not feature list)
```
Wrong (output): "Q2: ship dark mode, Q3: ship notifications"
Right (outcome): "Q2: increase D7 retention 15%→20% (initiatives: onboarding, notifications)"

Format — Now / Next / Later (commitment decreases over time):
NOW (this quarter, committed):
  Outcome: [measurable goal]
  Initiatives: [what we're building toward it]
  Confidence: HIGH

NEXT (next quarter, likely):
  Outcome: [goal]
  Confidence: MEDIUM (may shift based on Now learnings)

LATER (directional, not committed):
  Themes: [areas of investment]
  Confidence: LOW (intentionally flexible)
```

## OKR Structure
```
Objective:    qualitative, inspirational, time-bound (the "what")
  "Become the fastest checkout experience in our category"
Key Results:  quantitative, measurable, 3-5 per objective (the "how we know")
  KR1: reduce p95 checkout time from 8s to 3s
  KR2: increase checkout completion rate from 70% to 82%
  KR3: achieve NPS > 50 on checkout flow

Rules:
  - KRs measure OUTCOMES not tasks ("ship X" is not a KR)
  - 70% achievement = success (set ambitious, not sandbagged)
  - Max 3-5 objectives per team per quarter (focus > breadth)
```

## Prioritization Frameworks
```
RICE:    (Reach × Impact × Confidence) / Effort
         Reach: users affected/quarter | Impact: 0.25-3 scale | Confidence: % | Effort: person-months
         Use for: comparing features within a backlog

Kano:    Basic (must-have) / Performance (more=better) / Delight (unexpected)
         Use for: balancing table-stakes vs differentiators

Cost of Delay / WSJF: (business value + time criticality + risk reduction) / job size
         Use for: sequencing when timing matters (SAFe)

Opportunity scoring: importance × (importance − satisfaction)
         Use for: finding underserved needs (high importance, low satisfaction)
```

## Roadmap Anti-Patterns
```
Feature factory:      roadmap = list of features, no outcomes → building without learning
Date-driven fiction:  precise dates 12 months out → false certainty, broken promises
No kill criteria:     initiatives never stopped → zombie projects consume capacity
Everything is P0:      no prioritization → team thrashes, nothing ships well
Roadmap as contract:   stakeholders treat Later as committed → no flexibility to learn
```
