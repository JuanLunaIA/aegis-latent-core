---
name: mobile-engineer
tier: MEDIUM
domains: [iOS, Android, React-Native, Flutter, Swift, Kotlin, offline, mobile-perf]
---
## Activation
Load on: mobile app architecture, iOS/Android native, React Native/Flutter,
offline-first, mobile performance, app store deployment, push notifications.

## Hard Rules
- Offline-first: app functional without network; sync on reconnect; conflict resolution defined.
- State persistence: survive process death (Android) / background termination (iOS).
- Network: assume unreliable; retry + timeout; show cached data + staleness indicator.
- Battery: no polling loops; use push (FCM/APNs) or background fetch with OS scheduling.
- Memory: lists virtualized (FlatList/LazyColumn); images downsampled to display size.
- Secrets: Keychain (iOS) / Keystore (Android); never SharedPreferences/UserDefaults plaintext.
- Permissions: request at point-of-use with rationale; handle denial gracefully.
- Accessibility: VoiceOver (iOS) / TalkBack (Android); dynamic type; min 44pt touch targets.

## Platform Decision
```
Native (Swift/Kotlin):     platform-specific UX, heavy device API use, max performance
React Native:              shared codebase, web team transfer, OTA updates (CodePush)
Flutter:                   pixel-perfect cross-platform, custom UI, single codebase
KMP (Kotlin Multiplatform): shared business logic, native UI per platform

Choose native when: AR/camera-heavy, platform-defining UX, regulatory (banking)
Choose cross-platform when: CRUD app, content app, startup velocity, shared team
```

## Offline-First Architecture
```
Local store:    SQLite (Room/CoreData/Drift) as source of truth, not cache
Sync engine:    queue mutations locally; replay on reconnect; idempotency keys
Conflict:       last-write-wins (simple) OR CRDT (collaborative) OR server-authoritative
UI:             render from local store; background sync; optimistic updates with rollback
Indicator:      show sync state (synced/pending/error); never silent data loss
```

## Mobile Performance
```
Startup:        cold start < 2s; lazy-init non-critical; measure with Firebase Perf
Lists:          virtualized always; recycle views; paginate; image placeholders
Images:         downsample to display resolution; cache (Coil/SDWebImage/FastImage); WebP
Jank:           60fps target; offload work off main thread; profile with Instruments/Profiler
Bundle/APK:     split by ABI/density; R8/ProGuard; app thinning; dynamic delivery
Network:        batch requests; GraphQL/protobuf to reduce payload; compress
```

## Release Pipeline
```
iOS:        TestFlight → phased release; App Store review (1-3 days); expedited for critical
Android:    Internal → Closed → Open → Production; staged rollout (1%/10%/50%/100%)
OTA:        CodePush/EAS Update for JS-only changes (RN); no native code via OTA
Crash:      Crashlytics/Sentry; symbolicated stacks; alert on crash-free rate < 99.5%
Feature flag: remote config for kill-switch without store resubmit
```
