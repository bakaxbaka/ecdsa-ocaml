# Interface Megaplan — Fullstack Analysis Console

Supersedes nothing. This sits on top of `MEGAPLAN.md` and
`MERGED-IMPLEMENTATION-PLAN.md`, which stay authoritative for the library
roadmap. It covers one deliverable: a local web console that drives the existing
OCaml libraries and shows every public function with complete, live results.

## 0. Starting point (verified, not assumed)

`dune build` passes. All 16 test binaries pass. Reaching that state meant
repairing 76 defects left by a bad merge:

| Defect | Nature |
| --- | --- |
| `Nonce_checker` → `Analysis` | hard dependency cycle; dune rejects main-module reverse deps |
| `transaction/parser.ml` + `tx_parser.ml` | two modules both named `Parser` |
| `(modules ...)` in 4 dune files | silently excluded files other code referenced |
| `(wrapped false)` library | referenced through its wrapper name (`Bitcoin_tx.Types`) |
| `.gitignore` | merge-conflict markers and a stray PowerShell command |
| ``ripemd160.ml` `` | stray file, trailing backtick in the name |

Two findings that shape this plan:

1. **14 of 16 test suites never ran.** They are `(executable)` stanzas, which
   `dune runtest` ignores; only `(test)` stanzas run. All pass when invoked by
   hand, but the project has treated them as CI-covered when they are not.
2. **The one red suite was red because of its vectors.** `test_signature_extraction`
   used hex with odd nibble counts (63, 66); the helper's `String.length h / 2`
   silently truncated them, so every assertion tested a corrupt buffer.

### Doc/reality mismatches to correct

`MEGAPLAN.md` marks "Phase 4 — Storage (complete)" and "Phase 5 — Application and
CLI (complete)". `lib/storage` is an empty directory; there is no Cmdliner CLI.
Those phases are **not** complete. The console makes the gap visible.

## 1. Goal

A browser console that exposes **every** public function across the libraries,
returns **complete** results, computes live in the OCaml process, and runs the
whole pipeline end to end with each stage visible as it lands.

Non-goal: an address-targeted key-extraction workflow.

## 2. Stack

Recommended and what this plan assumes:

| Layer | Choice | Why |
| --- | --- | --- |
| Frontend | **Next.js 15 (App Router) + TypeScript** | real routing, route handlers for the proxy, streaming support, room to grow into more than one screen |
| Styling | **Tailwind CSS v4** | fast iteration, no CSS sprawl, easy to keep tokens consistent |
| Components | **shadcn/ui + Radix primitives** | accessible by default (focus, keyboard, ARIA) — not hand-rolled widgets |
| Data | **TanStack Query + TanStack Virtual** | request state and virtualized rendering of very large result arrays |
| Charts | **Recharts** | the statistics module produces distributions worth plotting |
| Package manager | **bun** if installed, else **npm** | detected at execution, not assumed |

React + Vite is the lighter alternative; Next is chosen for the proxy route
handlers and streaming, which is what makes live per-stage output clean.

### Architecture

```
web/                    Next.js app: UI + /api proxy
bin/server.ml           OCaml compute server (real work happens here)
lib/api/                json_encode · registry · endpoints
```

Two processes, one compute path:

- **OCaml server** owns all real computation. No shelling out per request.
- **Next.js** serves the UI and proxies `/api/*` to the OCaml server, forwarding
  streams unbuffered so NDJSON arrives incrementally.
- `lib/api/endpoints.ml` is a **pure** `route → json` dispatcher with no I/O, so
  it is testable without a socket.

Dev runs both with one command; `run-server.ps1` starts the pair and captures the
environment quirks (`libgmp-10.dll` and the switch's `stublibs` must be on
`PATH` — diagnosing that cost real time and should never be rediscovered).

## 3. API surface

129 `val`s across 24 `.mli` files, plus `type`/`module` members:

| Library | Module | vals |
| --- | --- | --- |
| crypto | `script` | 22 |
| crypto | `bytes_util` | 17 |
| crypto | `point` | 13 |
| crypto | `sig_analysis` | 8 |
| crypto | `signature` | 7 |
| analysis | `nonce` | 6 |
| bitcoin | `classify` | 6 |
| bitcoin | `types` | 6 |
| bitcoin | `bip143` / `legacy` / `hex` | 5 each |
| analysis | `analysis` / `statistics` | 4 each |
| crypto | `hash` | 4 |
| analysis | `observation`, `bitcoin/signature_extraction`, `tx_stream/nonce_checker` | 3 each |
| crypto | `der` / `verify`, `bitcoin/parser` | 2 each |
| `transaction_analysis`, `ripemd160` | 1 each |
| `field`, `scalar` | 0 (`module`-style interface) |
| `tx_parser` | 0 (`include module type of`) |

The catalogue generator must understand `module` and `include module type of` —
the two zero-`val` files are exactly what a naive regex reports as empty.

Three modules need wiring or documented exclusion before surfacing:
`lib/bitcoin/hash/hash160.ml`, `lib/analysis/types/signature_types.ml`,
`lib/bitcoin/network.ml`.

### Endpoints

`GET /api/health` · `/api/functions` · `/api/samples`

`POST /api/parse` · `/api/script/classify` · `/api/der/parse` ·
`/api/sighash/legacy` · `/api/sighash/bip143` · `/api/signatures/extract` ·
`/api/observation/build` · `/api/nonce/analyze` · `/api/statistics` ·
`/api/sig-analysis` · `/api/pipeline` (NDJSON stream, one object per stage)

`Z.t` always serialises as decimal **and** 64-char hex, never a JS number.

## 4. Non-truncation — a hard invariant

**Nothing is ever truncated**: not display, export, clipboard, response, or JSON.
Enforced by mechanism.

**Server**
- No default caps. No `max_results`, no `head`, no pagination that silently drops.
- Any limit must be opt-in, and the response carries `truncated: true` with
  `total`, `returned`, `reason`. A silent cut is a bug, not a tuning parameter.
- Large results stream as NDJSON rather than buffering into a shortened array.
- Every response echoes the full input that produced it.

**Client**
- `text-overflow: ellipsis` forbidden; so is `max-height` paired with
  `overflow: hidden` on a data container. A build-time grep fails on either.
- No `slice`/`substring`/`truncate` on data paths.

**Completeness asserted, not assumed**
- Every result header prints declared vs rendered counts.
- A runtime check compares them and shows a red `INCOMPLETE` badge naming both
  numbers on mismatch. The console never claims completeness it has not verified.

**Virtualization, stated precisely**
Large arrays virtualise the *viewport* for performance. The data model is always
complete: nothing is dropped, and search, copy, export, and counts all operate on
the full array — never on the rendered window. A test asserts
`model == exported == copied`, and that every index is reachable by scroll or
search. If virtualization cannot be shown to preserve that, batching replaces it;
correctness outranks smoothness.

**Views and export — all complete**
- Three views per result: JSON tree, raw text, hex.
- Copy copies the full serialised JSON, never the rendered DOM.
- Session export as `.jsonl` (streams without buffering) and `.txt`.
- Tree collapse state is display-only; every node is present in exported data.

## 5. Design

Aim: look like a serious instrument, not a dashboard template. Reference points
are Linear, Warp, and Vercel — restrained, dense, confident.

Dark base, flat surfaces, hairline borders, no decorative gradients or glow.

| Token | Value |
| --- | --- |
| base | `#0b0d10` |
| panel | `#14171c` |
| raised | `#1a1e24` |
| border | `#262b33` |
| text | `#e6e9ef` |
| text-dim | `#9aa3b2` |
| accent | `#4dd0e1` |
| warn | `#ffb454` |
| danger | `#ff5c5c` |
| ok | `#52c41a` |

Typography: data in `ui-monospace, "Cascadia Mono", Consolas, monospace`; UI in
the system sans stack. 13px base, 1.45 line-height, 4px spacing scale. Numbers
right-aligned and tabular-figured so columns line up.

Shell: top bar (brand, backend status, latency, export) · left rail (catalogue,
searchable, grouped by library, collapsible) · main workspace with tabs
(**Catalogue · Pipeline · Results · Charts**) · resizable panels. Single column
under 1100px. Light theme included via tokens.

Details that carry the quality: `⌘K` command palette jumping to any of the 129
functions; inline typed input forms derived from each `.mli` signature rather
than a raw JSON textarea; per-result timing; keyboard-only operability
throughout; focus rings preserved; WCAG AA contrast verified.

Charts are paired with full data tables — a chart never becomes the only way to
see a value.

## 6. Verification

- Every endpoint run against real raw transactions, compared byte-exact to
  direct CLI output (`bin/analyse_txs.exe`, `tools/dump_rsz.exe`).
- **Truncation guard**: synthetic 100k-signature result must render, export and
  copy with `declared == model == exported == copied`.
- **Stylesheet guard**: build fails on `text-overflow: ellipsis` or `max-height`
  + `overflow: hidden` in a data container.
- **No silent caps**: every response checked for absence of `truncated` unless a
  limit was explicitly requested.
- Playwright pass: navigate every tab, run every function, assert counts.
- Keyboard-only pass and contrast check.
- `dune build` and all 16 suites re-run after every change.

## 7. Risks

| Risk | Mitigation |
| --- | --- |
| No `cohttp` in the Windows switch | minimal `unix`-based server; decided early, reported |
| No bun/node toolchain for Next | detected in step 1; fall back to Vite React or npm |
| Huge results freeze the DOM | virtualized viewport with a complete data model; guard test |
| Catalogue drifts from code | generated from `.mli`, never hand-written |
| `Z.t` precision loss in JS | decimal + hex strings only |
| Two processes feel heavy | one command starts both; Next proxies, so no CORS |

## 8. Also in scope

- Remove scratch generators `tools/_fix_test_vectors.py`, `tools/_gen_test_vectors.py`.
- Repair `.gitignore`.
- `run-server.ps1` capturing the DLL/`stublibs` PATH requirement.
- Convert the 14 `(executable)` test stanzas to `(test)` so `dune runtest`
  actually runs them — otherwise CI keeps reporting green on suites it never
  executes.

## 9. Delivered

1. `lib/api/` — encoders, catalogue, dispatcher.
2. `bin/server.ml` — compute server, NDJSON streaming, no default caps.
3. `web/` — Next.js console.
4. `run-server.ps1` and usage docs.
5. `.gitignore` repaired, scratch removed, test stanzas converted.
6. Verification report: every endpoint, its inputs, observed output.
