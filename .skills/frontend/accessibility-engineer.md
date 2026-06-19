---
name: accessibility-engineer
tier: MEDIUM
domains: [WCAG, ARIA, a11y, screen-reader, keyboard-nav, contrast, focus]
---
## Activation
Load on: accessibility audit, WCAG compliance, ARIA usage, screen reader support,
keyboard navigation, color contrast, focus management, a11y testing.

## WCAG 2.2 AA Requirements (legal baseline US/EU)
```
Perceivable:
  1.1.1  Non-text content has text alternative (alt, aria-label)
  1.3.1  Info/relationships in markup (headings, lists, landmarks, labels)
  1.4.3  Contrast: 4.5:1 text, 3:1 large text (18pt+/14pt bold), 3:1 UI components
  1.4.10 Reflow: usable at 320px width without horizontal scroll
  1.4.11 Non-text contrast: 3:1 for UI components and graphical objects

Operable:
  2.1.1  All functionality keyboard-accessible
  2.1.2  No keyboard trap (can tab out of any component)
  2.4.3  Focus order logical and meaningful
  2.4.7  Focus visible (never outline:none without replacement)
  2.5.8  Target size: 24×24px minimum (44×44 recommended mobile)

Understandable:
  3.2.1  No context change on focus
  3.3.1  Error identification (which field, what's wrong)
  3.3.2  Labels/instructions for inputs

Robust:
  4.1.2  Name/role/value for all UI components (native or ARIA)
  4.1.3  Status messages announced (aria-live)
```

## ARIA Rules (use sparingly)
```
Rule 1: Use native HTML element if it exists (<button> not <div role="button">)
Rule 2: Don't change native semantics (don't put role="heading" on <button>)
Rule 3: All interactive ARIA must be keyboard-operable
Rule 4: Don't use role="presentation" on focusable elements
Rule 5: All form inputs need accessible name (label, aria-label, aria-labelledby)

Common patterns:
  Modal:       role="dialog" aria-modal="true" + focus trap + Escape + restore focus
  Live region: aria-live="polite" (status) / "assertive" (errors)
  Tabs:        role="tablist/tab/tabpanel" + arrow key navigation + aria-selected
  Combobox:    aria-expanded + aria-controls + aria-activedescendant
  Disclosure:  aria-expanded on trigger + aria-controls
```

## Testing Pipeline
```bash
# Automated (catches ~40% of issues — necessary, not sufficient)
axe-core / @axe-core/playwright   # in E2E tests
pa11y-ci                          # CI gate
lighthouse --only-categories=accessibility

# Manual (catches the other 60%)
- Keyboard only: unplug mouse, navigate entire flow
- Screen reader: VoiceOver (Mac) / NVDA (Windows) / TalkBack (Android)
- Zoom 200%: content reflows, nothing cut off
- Contrast: check all text + UI against WCAG ratios
```

## Common Failures + Fixes
```
outline: none           → provide :focus-visible alternative; never remove without replacement
div onClick             → use <button>; add keyboard handler if div mandatory
placeholder as label    → add real <label>; placeholder disappears on input
icon-only button        → add aria-label describing action
color-only indication   → add icon/text (colorblind users); error ≠ red-only
auto-playing carousel    → pause control; respect prefers-reduced-motion
missing skip link       → <a href="#main">Skip to content</a> as first focusable
```
