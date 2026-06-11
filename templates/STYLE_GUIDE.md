# Report v2 Style Guide

Design tokens and patterns for `templates/report_v2.html.j2`.

## Color palette

| Token | Hex | Usage |
|-------|-----|--------|
| `--color-primary` | `#1F4E79` | Headers, primary actions, hero number |
| `--color-accent` | `#2E75B6` | Links, graph entry points, highlights |
| `--color-danger` | `#C53030` | BLOCK verdict, critical badges |
| `--color-warning` | `#D69E2E` | REVIEW verdict, amber states |
| `--color-success` | `#38A169` | PROCEED verdict, patched state |
| `--color-surface` | `#F8FAFC` | Page background |
| `--color-card` | `#FFFFFF` | Cards and panels |
| `--color-text` | `#1A202C` | Body text |
| `--color-muted` | `#718096` | Secondary text, de-emphasized stats |
| `--color-border` | `#E2E8F0` | Dividers and card borders |

Use color **only** for severity and status — not decoration.

## Typography

- **Sans:** Inter (CDN / `static/vendor/inter.css`), fallback system-ui
- **Mono:** JetBrains Mono, Consolas — commands, code, formula

| Token | Size | Use |
|-------|------|-----|
| `--text-xs` | 12px | Badges, meta, legend |
| `--text-sm` | 14px | Table body, step reasons |
| `--text-base` | 16px | Body default |
| `--text-lg` | 20px | Section titles, narrative |
| `--text-xl` | 25px | Secondary stat numbers |
| `--text-hero` | 96px | Hero reachable count (64px on mobile) |

Limit any single section to **three** distinct font sizes.

## Spacing

4px base: `--space-1` (4) through `--space-16` (64).

- Card padding: `--space-6`
- Section gaps: `--space-8`
- Hero padding: `--space-12`

## Radius & shadow

- `--radius-sm` (6px): buttons, inputs
- `--radius-md` (12px): cards, step cards
- `--radius-lg` (16px): hero panel
- `--shadow-sm` / `--shadow-md` / `--shadow-lg`: cards; hover promotes one level

## Components

### Verdict badge

`.verdict-BLOCK` | `.verdict-REVIEW` | `.verdict-PROCEED` — header pill with score subline.

### Hero fraction

Single visual: large reachable count + smaller “of N” + subtitle. Not four equal cards.

### Action / step card

Left accent border (`--color-primary`), copy-to-clipboard on commands, estimated time top-right.

### Badge

Pill shape for verdicts and patch change classifications. Map:

- `HARDENED_ONLY` → grey-green
- `SIGNATURE_CHANGED`, `RENAMED` → red
- `RETURN_CHANGED` → amber
- `INTERNAL_CHANGE`, `ADDED`, `REMOVED` → grey

### Risks table

Expandable rows; score breakdown as horizontal bars (max width = component cap).

### Graph legend

Fixed bottom-left; node colors match vis-network styling.

## Tab structure

| Tab | Question |
|-----|----------|
| Overview | Should I worry? |
| Risks | What did you find, and where? |
| Fix Plan | What do I do now? |
| Patches | What did each patch change? |
| Graph | How does my code reach these? |
| Audit | How do I know this is correct? |

## Accessibility

- `role="tablist"` / `tab` / `tabpanel` with `aria-selected`
- Arrow keys on tab bar
- WCAG AA contrast on text and badges
- Mobile: tab bar → `<select>` below 768px

## Print

All tabs print sequentially; hide nav, filters, copy buttons; force light background.
