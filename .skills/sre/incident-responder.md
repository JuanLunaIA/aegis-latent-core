---
name: incident-responder
tier: HIGH
domains: [P0, P1, war-room, RCA, incident-coordination, on-call]
---
## Activation
Load on: active incident, "we're down", "production issue", P0/P1 coordination,
mitigation steps, war room, customer communication during outage.

## Severity Matrix
```
P0  Service unavailable or data loss for ≥ 5% users | page all on-call immediately
P1  Degraded service for ≥ 20% users OR SLO breach  | page primary on-call
P2  Partial degradation < 20% users                  | async ticket, fix in 4h
P3  Minor issue, no customer impact                  | normal sprint
```

## First 5 Minutes Protocol
```
1. DECLARE     Announce incident in #incidents: "P[N] declared: [symptom] at [HH:MM UTC]"
2. ASSIGN      Incident Commander (IC), Communications Lead, Tech Lead — one person per role
3. BRIDGE      Open war room (Zoom/Meet/Slack huddle); IC facilitates, not debugs
4. SNAPSHOT    Capture current state: dashboards, error rate, affected % users
5. MITIGATE    Is there a rollback available? Try rollback BEFORE diagnosis if severity is P0
```

## Incident Commander Responsibilities
```
Every 15 min: status update to #incidents + status page
Every 30 min: brief leadership if P0 > 30 min unresolved
Decisions:    IC decides; IC does NOT debug
Scribe:       all actions timestamped in incident doc in real-time
```

## Mitigation-First Principle
```
Priority order:
1. Rollback last deploy (fastest; try within first 10 min of P0)
2. Feature flag off (if feature-flagged change)
3. Disable affected endpoint / put in maintenance mode
4. Scale up resources (if capacity-related)
5. Identify and fix root cause (AFTER service is restored)

Never: keep service down to preserve evidence (snapshot first, then mitigate)
```

## Incident Document Template (live during incident)
```markdown
# Incident: [title] | Severity: P[N] | Started: HH:MM UTC
IC: [@name] | Comms: [@name] | Tech Lead: [@name]

## Current Status
[one-line status, updated every 15 min]

## Timeline
HH:MM — [observation or action]

## Hypotheses Under Investigation
[ ] [hypothesis] — [evidence for/against]
[x] [hypothesis] — RULED OUT because [reason]

## Actions Taken
HH:MM — [@who] did [what] → result: [outcome]

## Open Questions
- [question] → [@owner]

## Impact
Users affected: ~[N] | Revenue impact: ~$[N]/hr | Started: HH:MM UTC
```
