---
name: technical-comms
tier: LOW
domains: [launch-announcements, blog, customer-notifications, deprecation, incident-comms]
---
## Activation
Load on: launch announcement, blog post, customer notification, deprecation notice,
incident customer communication, status page update.

## Audience-Tone Matrix
```
Internal engineering:  direct, technical depth, no softening
Internal leadership:   impact-first (business metric), then mechanism, brief
Customer (technical):  clear, honest, actionable, no jargon without definition
Customer (general):    plain language, what it means for them, what to do
Public/press:          polished, no speculation, legal-reviewed before send
```

## Incident Communication Templates
```
[STATUS PAGE — first update, within 15 min of detection]
We are investigating an issue affecting [service]. Some users may experience
[symptom]. We will provide an update in 30 minutes.

[STATUS PAGE — identified]
We have identified the cause of [symptom] affecting [scope]. Our team is
actively working on a fix. Estimated resolution: [time range or "under investigation"].

[STATUS PAGE — resolved]
The issue affecting [service] has been resolved as of [HH:MM UTC].
[N] users were impacted over [duration]. We will publish a postmortem within 48 hours.

[CUSTOMER EMAIL — significant incident]
Subject: [Action Required / Service Update]: [Brief description]
- What happened: [plain language, no internal jargon]
- Who was affected: [specific scope]
- What we did: [steps taken]
- What you need to do: [if anything]
- What we're doing to prevent recurrence: [1-3 concrete items]
```

## Deprecation Notice Template
```
Subject: [Feature/API] deprecation — action required by [DATE]

[Feature] will be deprecated on [DATE] and removed on [DATE + 6 months].

**Why**: [honest reason — not "we're improving things"]
**Migration path**: [exact steps, link to migration guide]
**Timeline**:
  - Today: deprecation warnings enabled (check your logs for "DEPRECATED: ...")
  - [DATE-2mo]: reduced functionality
  - [DATE]: end of life

Questions: [channel/email]
```
