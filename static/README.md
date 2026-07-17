# Vantage frontend assets

Everything the UI needs at runtime lives here. **Vantage makes no network request
to any third party when rendering a page** — no CDN, no font service, no
telemetry. That is a hard requirement, not a preference: Vantage is meant to run
on a VPN-only box with no egress, and a control plane that phones out to render
its own dashboard is a control plane you cannot audit. If you add an asset, vendor
it here; do not add a `<link>`/`<script>` pointing at someone else's host.

Vantage also does **not** use the `kls-ui` shared design system (dropped in the
frontend rewrite). `kls-ui` still serves klappstuhl.me and the Percy dashboard;
Vantage owns its own look so it can ship standalone.

## Layout

```
css/
  tokens.css       design tokens: palettes (dark/light), accent presets, density, scale
  base.css         reset, @font-face, element defaults, typography, a11y primitives
  components.css   the component library (btn, card, stat, table, modal, toast, …)
  shell.css        the app frame: sidebar, topbar, content, responsive drawer
  pages/*.css      per-page composition only; loaded by that page's template
js/
  core/*.js        shared runtime (api, live, ui, format, chart, theme, palette, shell, widgets)
  pages/*.js       one module per page; runs on load, exports nothing
fonts/*.woff2      IBM Plex Sans (400/500/600) + IBM Plex Mono (400/500), latin subset
icons/sprite.svg   generated Lucide subset; see below
vendor/*           third-party libraries, unmodified
```

CSS is layered — `@layer tokens, base, components, shell, pages` — so page CSS can
always override a component without `!important` or selector escalation. The
cascade order is fixed by the `@layer` statement in `tokens.css`, not by link order.

## Vendored third-party assets

| Asset | Version | License | Source |
|---|---|---|---|
| `vendor/uplot.iife.min.js`, `vendor/uplot.min.css` | 1.6.31 | MIT | https://github.com/leeoniya/uPlot |
| `vendor/cytoscape.min.js` | 3.29.2 | MIT | https://github.com/cytoscape/cytoscape.js |
| `fonts/plex-*.woff2` | IBM Plex 5.x (via @fontsource) | OFL-1.1 | https://github.com/IBM/plex |
| `icons/sprite.svg` | lucide-static 0.469.0 | ISC | https://github.com/lucide-icons/lucide |

Vendored files are kept **unmodified** so they can be re-fetched and diffed. The
one generated artifact is the icon sprite.

## Tooling

The scripts that maintain this directory live in `scripts/`, **not here** —
everything under `static/` is served publicly by `ServeDir`, and a build script
is not an asset.

| Script | Purpose |
|---|---|
| `scripts/check_assets.py` | Fails if any `/static/...` reference in a template/CSS/JS has no file behind it. Askama can't catch this; a missing asset is a silent 404. |
| `scripts/check_imports.py` | Walks the ES-module graph: every relative import resolves, every named import exists, no import is unused. A bad named import is a runtime SyntaxError on one page only. |
| `scripts/check_contrast.py` | WCAG audit of the real `tokens.css` — every text pair at 4.5:1, control borders at 3:1, in both themes and all five accents. |
| `scripts/build_sprite.py` | Regenerates `icons/sprite.svg`. |

All four exit non-zero on failure and are CI-ready. The first three are the
frontend's test suite — `cargo test` cannot see any of what they check.

## Regenerating the icon sprite

`icons/sprite.svg` is generated from a curated Lucide subset (the `ICONS` list
in the script). To add an icon: add its Lucide name to the list and re-run:

```bash
python scripts/build_sprite.py static/icons/sprite.svg
```

The script strips each icon's stroke presentation attributes on purpose, so the
`.icon` CSS class controls stroke width and color by inheriting into the `<use>`
shadow tree. Use icons as:

```html
<svg class="icon" aria-hidden="true"><use href="/static/icons/sprite.svg#shield"/></svg>
```

An icon that carries meaning on its own (an icon-only button) needs an
accessible name on the *button*, not the `<svg>` — the sprite is always
`aria-hidden`.
