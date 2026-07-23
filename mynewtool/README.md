# FeatureMapper — Attack Surface Recon

A browser extension for bug-bounty hunters. **Just browse the target app** — FeatureMapper
watches the page and automatically builds a **live, nested tree of every feature** you touch:
nav items, tabs, order-type toggles, buttons, form inputs, dropdown menu items — organized
exactly like the app's UI hierarchy (`Copy Trading → Plaza → Leaderboard → Copy button`).

No manual note-taking. Export the whole map as a **Markdown checklist** or **JSON** when done.

## What counts as a "feature"

- **Pages / routes** you visit (incl. SPA route changes) — the top level.
- **Sections** — nav bars, forms, dialogs/modals, tab groups, dropdown menus, panels.
- **Controls** — links, buttons, tabs, menu items, inputs, checkboxes, toggles, selects.

Everything nests: a control lives under its section, a section under its page. Features within
features, mirroring what you see on screen.

## Features of the tool

- **Fully automatic capture** while you browse (MutationObserver + re-scan after clicks, so
  menus/modals that open on interaction get captured too).
- **Live side panel** (docked right). Toggle with the 🎯 launcher (bottom-right).
- **Hover a node → the element highlights on the page**; click → scrolls to it.
- **👁 Reveal Hidden** (optional, one click, reversible) — force-shows `display:none` /
  `[hidden]` / `visibility:hidden` / zero-opacity elements, flips `input[type=hidden]` to
  visible text, enables `disabled`/`readonly` controls, strips client-side validation
  (`required`, `pattern`, `maxlength`, form `novalidate`), and promotes lazy `data-src` images.
  Revealed elements get an amber dashed outline, and the scanner re-runs so the newly-exposed
  forms/buttons drop straight into your feature tree. Click again to restore the page exactly.
- **Per-feature "tested" checkboxes** — turn the map straight into a testing checklist.
- **Filter box** to search the tree.
- **Per-origin persistence** — the map for each target is saved and restored automatically.
- **Export**: nested Markdown checklist (`- [ ] **Buy** \`button\``) or full JSON tree.
- **Pause/Resume** recording; **Clear** per target.

## Install (Chrome / Edge / Brave)

1. Go to `chrome://extensions`.
2. Enable **Developer mode** (top-right).
3. Click **Load unpacked** and select this folder (`mynewtool`).
4. Open any web app. Click the 🎯 button bottom-right to open the panel and start mapping.

## Install (Firefox)

1. Go to `about:debugging#/runtime/this-firefox`.
2. Click **Load Temporary Add-on** and select `manifest.json` in this folder.

## Notes / roadmap

- Scanning runs on every site by default; use **Pause** on pages you don't want mapped, or
  narrow `matches` in `manifest.json` to your target domains.
- v1 captures light-DOM elements. Elements inside closed shadow roots and cross-origin iframes
  are not yet traversed.
- Planned: scope/allow-list per program, named projects, associating popups with their trigger,
  capturing the underlying request (method/params) per control, and role/session tagging for
  authz/IDOR diffing.
