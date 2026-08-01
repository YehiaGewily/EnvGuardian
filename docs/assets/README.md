# Brand assets

## Active mark: keyhole 🔑

A shield with an inner keyhole, emerald→teal gradient. Symbolizes secure access to
configuration.

### Files

| File | Use |
|---|---|
| `logo-mark.svg` | Icon-only mark (128×128, scales cleanly). |
| `logo-horizontal.svg` | Icon + "EnvGuardian" wordmark, dark text — for **light** backgrounds. |
| `logo-horizontal-dark.svg` | Icon + wordmark, light text — for **dark** backgrounds. |
| `logo-horizontal.png` / `-dark.png` | 600 px raster fallbacks (2× retina) for the two lockups. |

### Favicons

| File | Use |
|---|---|
| `favicon.svg` | Modern browsers — scalable, sharp at every size. Preferred. |
| `favicon.ico` | Classic Windows/legacy fallback. Contains 16/32/48 px frames. |
| `favicon-16.png` / `-32.png` / `-48.png` | Individual PNGs if a specific size is needed. |
| `apple-touch-icon.png` | 180 × 180, referenced by iOS home-screen bookmarks. |

### Recommended HTML

For a future docs site or landing page:

```html
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="alternate icon" href="/favicon.ico">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
```

For the README (already wired), the SVG-with-PNG-fallback lockup uses a `<picture>` tag so
the dark version shows automatically on dark themes and PNG serves any renderer that
rejects inline SVG.

## Colors

- Steel 400 `#5B8DC9` — gradient start
- Steel 700 `#2C5480` — gradient end
- Steel 500 `#3B6EA5` — the "Env" in the light wordmark
- Steel 300 `#7DA9DA` — the "Env" in the dark wordmark
- Slate 800 `#1E293B` — the "Guardian" in the light wordmark
- Slate 200 `#E2E8F0` — the "Guardian" in the dark wordmark

## Archived concepts

`old-designs/` holds two runner-ups (terminal `>_` and key). They are **not** used
anywhere in the project — kept only for reference.
