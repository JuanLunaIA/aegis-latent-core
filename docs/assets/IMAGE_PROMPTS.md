# README Image Prompts — copy-paste into ChatGPT / DALL·E / Midjourney

This project already ships its own **vector visuals** (the hero banner, the
compliance trust-strip and the "how it works" guide are the `*.svg` files in
this folder — they render natively on GitHub in both light and dark mode). They
are crisp at any size, weigh a few kilobytes each, and never call out to an
external server.

If you also want **photographic / rendered hero art** to drop in (a wide cover
image, a section divider, social-preview card, etc.), the prompts below are
written to be pasted straight into an image model. They assume the model knows
**nothing** about this project, so each prompt fully describes the scene, style,
palette, framing and what to avoid. Just copy a whole block.

---

## House style (applies to every prompt)

- **Palette:** deep graphite / near-black background `#0d1117`, cool slate panels
  `#161c26`, with a confident royal-blue `#2f5bea` and a teal-cyan `#0e8caa`
  accent. Optional supporting hues: emerald `#1f9d6b`, soft amber `#bd7d0d`.
  Mostly desaturated and calm; accent colour used sparingly.
- **Mood:** institutional, trustworthy, precise — the visual language of an
  enterprise security / compliance product, not a gaming or crypto brand.
- **Lighting:** soft, even studio light with one gentle accent rim-light. No
  harsh lens flares.
- **Always avoid:** any text, letters, numbers, logos or watermarks (image
  models render them as garbled glyphs); neon cyberpunk clichés; glowing green
  "Matrix" code rain; cartoonish padlocks; stock-photo people in suits pointing
  at floating holograms; busy clutter; heavy vignettes.
- **Aspect ratio:** a wide README cover reads best around **1280 × 440 px**
  (≈ 21:9). Section dividers ≈ **1280 × 240**. Social-preview card **1280 × 640**
  (GitHub Open-Graph). State the ratio explicitly in your image tool.
- **Export:** generate a light-background and a dark-background variant if you
  want theme-aware swapping, then save as `docs/assets/<name>-light.png` /
  `-dark.png` and reference them with a `<picture>` block like the SVGs in the
  README.

---

## Prompt 1 — Primary hero cover ("the verifiable control plane")

```
A wide, ultra-clean enterprise technology hero image, 21:9 aspect ratio, for a
software security product. Centre-right of the frame: an elegant 3D translucent
shield made of frosted glass and brushed aluminium, floating in soft focus.
Inside the shield, a neat vertical stack of small rounded rectangular "data
blocks" is connected top-to-bottom by thin glowing links, like a chain of
sealed ledger entries; a single small circular seal with a simple check mark
glows at the top of the shield in royal blue. The background is a deep graphite
near-black studio gradient (#0d1117) with an extremely subtle large-dot grid and
one soft royal-blue (#2f5bea) and teal-cyan (#0e8caa) volumetric glow behind the
shield. Minimalist, premium, lots of negative space on the left third for a
title to be added later. Soft even lighting, gentle rim light on the shield
edge, shallow depth of field. Corporate, trustworthy, high-end fintech /
govtech aesthetic. Photorealistic 3D product render, octane-style, crisp.
No text, no letters, no numbers, no logos, no watermark. No neon, no Matrix code,
no cartoon padlocks.
```

## Prompt 2 — Tamper-evident audit chain (concept / section divider)

```
A clean, minimalist 3D illustration, very wide 21:9 banner, on a deep graphite
background (#0d1117). A single horizontal chain of identical small frosted-glass
cubes recedes into soft focus from left to right; each cube is linked to the
next by a thin luminous royal-blue (#2f5bea) thread, and a faint cyan (#0e8caa)
hash-pattern texture is etched on each face. One cube near the centre is lifted
slightly and sealed with a tiny glowing wax-seal-style disc bearing a simple
check mark. The composition suggests an unbreakable, ordered, sealed record.
Generous empty space above and below. Soft studio lighting, subtle reflections
on a dark matte floor, shallow depth of field. Premium, institutional, calm.
Photorealistic product render. No text, no letters, no numbers, no logos, no
watermark, no neon glow, no circuit-board clichés.
```

## Prompt 3 — Governance gateway / two-path flow

```
A premium isometric 3D diagram-style illustration, 21:9, on a dark slate
gradient background (#0d1117 to #161c26). On the left, a stream of soft white
glowing particles flows along a clean channel toward a central elegant gateway
arch made of brushed metal and frosted glass. At the gateway, the stream passes
through a thin translucent royal-blue (#2f5bea) filter membrane and continues to
the right toward a softly glowing sphere (representing a remote service). Below
the main channel, a separate, quieter secondary path branches downward into a
small sealed vault cube with a cyan (#0e8caa) check-seal — clearly an
"after the fact" side path, not blocking the main flow. Minimal, airy, lots of
negative space, soft even lighting, subtle depth of field. Enterprise
infrastructure aesthetic, trustworthy and precise. Photorealistic render.
No text, no letters, no numbers, no logos, no watermark, no neon, no clutter.
```

## Prompt 4 — Regulated-industries mosaic (abstract, logo-free)

```
A sophisticated, abstract wide banner (21:9) on a deep graphite background
(#0d1117) suggesting many regulated sectors protected under one system, WITHOUT
any real logos or text. A softly lit grid of simple, elegant 3D glass icons
floats in gentle perspective: a hospital cross, a bank/columned building, a
government dome, a factory gear, a scales-of-justice, a microchip, a shield.
Each icon is frosted glass with a thin royal-blue (#2f5bea) or teal-cyan
(#0e8caa) edge light, arranged on an invisible grid with calm spacing. A faint
network of thin lines connects them, and one subtle shield watermark sits behind
the whole cluster. Muted, desaturated, premium, institutional. Soft studio
lighting, shallow depth of field, lots of negative space. Photorealistic 3D
render. No text, no letters, no numbers, no brand logos, no flags, no watermark,
no neon, no people.
```

## Prompt 5 — Post-quantum seal (close-up focal image, square or 4:3)

```
A macro, photorealistic 3D product render of a single circular cryptographic
"seal" medallion, 1:1 square framing, on a dark graphite background (#0d1117). The
medallion is brushed titanium with a frosted royal-blue (#2f5bea) glass inlay and
a simple engraved check mark at its centre; a fine concentric lattice pattern
(suggesting a mathematical lattice) is etched into the metal rim, catching a soft
cyan (#0e8caa) rim light. Tiny particles drift around it. Extremely clean,
high-end, jewelry-product-photography lighting on a dark reflective surface,
shallow depth of field, single soft key light plus gentle accent. Premium,
serious, futuristic-but-restrained. No text, no letters, no numbers, no logos, no
watermark, no neon glow, no cartoon style.
```

## Prompt 6 — Subtle section-divider texture (very wide, low-contrast)

```
An extremely subtle, low-contrast decorative divider strip, very wide panoramic
ratio (about 6:1), on a deep graphite background (#0d1117). A faint horizontal
field of tiny connected nodes and thin lines fades in from fully transparent
edges, with a single soft royal-blue (#2f5bea) gradient glow drifting through the
centre and a whisper of teal-cyan (#0e8caa). Mostly empty, atmospheric, calm —
meant to sit quietly between sections of a document without competing for
attention. Minimalist, elegant, premium. No text, no letters, no numbers, no
logos, no watermark, no bright neon, no busy detail.
```

---

## How to wire a generated raster image into the README

```html
<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/hero-photo-dark.png">
  <img alt="Short, descriptive alt text of what the image shows" src="docs/assets/hero-photo-light.png" width="100%">
</picture>

</div>
```

Keep raster files reasonably small (target < 400 KB; export at ~1600 px wide and
let the browser scale down). The committed SVGs remain the default; raster art is
an optional enhancement you can swap in per section.
```
