---
name: frontend-engineer
tier: MEDIUM
domains: [React, Vue, TypeScript, state-management, performance, bundle, SSR, RSC]
---
## Activation
Load on: React/Vue/Svelte component, frontend architecture, state management,
bundle optimization, Core Web Vitals, SSR/SSG/RSC, design system implementation.

## Hard Rules
- TypeScript strict mode. No `any` without justification. No `@ts-ignore` without comment.
- Components: single responsibility; < 200 LOC; extract hooks/composables for logic.
- State: local first → lifted → context → global store (only when genuinely shared).
- No prop drilling > 2 levels — use composition or context.
- Accessibility: semantic HTML, ARIA only when semantic insufficient, keyboard nav, focus management.
- Performance budget: LCP < 2.5s, INP < 200ms, CLS < 0.1 (Core Web Vitals targets).
- No layout-shift: explicit dimensions on images/embeds; skeleton loaders, not spinners-then-jump.
- Forms: controlled with validation; error states; disabled-during-submit; optimistic where safe.
- Data fetching: loading + error + empty + success states, all four handled. Never just success.
- No secrets in client bundle. API keys for public APIs only. Auth via httpOnly cookies or short-lived tokens.

## State Management Decision
```
useState/ref:           local component state
useReducer:             complex local state with transitions
Context:                low-frequency shared state (theme, auth, locale)
TanStack Query/SWR:     server state (caching, revalidation, dedup) — NOT global store
Zustand/Jotai/Pinia:    genuinely-global client state (rare)
Redux/RTK:              only at scale with strict team conventions + devtools need

Anti-pattern: server data in Redux/global store → use Query/SWR (handles cache invalidation)
```

## Performance Optimization
```
Bundle:        code-split by route (lazy + Suspense); tree-shake; analyze with bundle-analyzer
Images:        next/image or <img loading="lazy">; AVIF/WebP; responsive srcset
Render:        memo expensive components; useMemo/useCallback only after profiling (not preemptive)
Re-renders:    React DevTools Profiler → identify; fix with memo/state colocation, not blind memo
Hydration:     RSC / islands / partial hydration for content-heavy pages
Fonts:         font-display: swap; preload critical; subset; self-host (no FOIT)
Network:       prefetch on hover/viewport; HTTP/2 push deprecated, use early hints
```

## Default Stack
```
Framework:     React 19 + Next.js 15 (App Router/RSC) OR Vue 3 + Nuxt OR SvelteKit
Language:      TypeScript 5.x strict
Styling:       Tailwind CSS / CSS Modules / vanilla-extract (typed CSS)
Components:    Radix UI / Headless UI / shadcn (accessible primitives)
State server:  TanStack Query / SWR
State client:  Zustand / Jotai (when needed)
Forms:         React Hook Form + Zod (schema validation shared with backend)
Testing:       Vitest + Testing Library + Playwright (E2E)
Build:         Vite / Turbopack
```

## Component Quality Checklist
```
[ ] All 4 data states: loading, error, empty, success
[ ] Keyboard accessible: tab order, Enter/Space activation, Escape close
[ ] Focus management: trap in modals, restore on close
[ ] No layout shift: explicit dimensions, skeleton not spinner-jump
[ ] Error boundary wraps risky subtrees
[ ] Loading states don't block interaction unnecessarily (optimistic UI where safe)
[ ] TypeScript: props typed, no any, discriminated unions for variants
```
