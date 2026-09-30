# Operator console — UI specification

This is a map of the interface onto what the repository actually contains. Where
a capability exists it is marked ✅ and names the file it comes from. Where the
design brief asked for something the repository does not have, it is marked ⛔ and
says what is missing. Nothing is described as working unless it was run.

---

## 0. Inventory

### 0.1 The brief's assumed system does not exist here

The brief specifies a full-stack OCaml Operator with sessions, a WebSocket
stream, `Executor` functions, `value_kind`, and Dream routes. Checked against the
source:

| Assumed | Present | Evidence |
| --- | --- | --- |
| `lib/domain/types.ml` | ⛔ absent | only `lib/bitcoin/transaction/types.ml`, which models Bitcoin transactions |
| `session_id`, `execution_id` | ⛔ absent | no match in `lib/`, `bin/`, `test/`, `tools/` |
| `exec_status` (`Queued`…`Killed`) | ⛔ absent | no match |
| `value_kind` (`Int`…`Opaque`) | ⛔ absent | no match |
| `execution_result`, `source_file`, `session` | ⛔ absent | unrepresented in any interface |
| `lib/engine/executor.ml` and its 8 functions | ⛔ absent | no `lib/engine/`; no `Executor` identifier |
| Dream | ⛔ absent | not in `dune-project`; no `Dream` reference anywhere |
| `Lwt` | ⛔ absent | no reference in `lib/`, `bin/`, or `test/` |
| `Handlers.Session` / `Exec` / `File` / `Ws` | ⛔ absent | no `Handlers` module |
| WebSocket endpoint | ⛔ absent | `bin/server.ml` is a hand-rolled `Unix` accept loop, `Connection: close` |
| File CRUD routes | ⛔ absent | the server reads files only to serve a built frontend |
| Auth, rate limiting, per-execution temp dirs | ⛔ absent | no such code |
| Melange / TyXML / Bonsai | ⛔ absent | not in the dependency set |

A UI built to that brief would render sessions that cannot be created, values that
cannot be produced, and a socket that cannot connect. It is not specified here.

### 0.2 What the repository does contain

**Analysis pipeline** — `lib/analysis/analysis.mli`:

```ocaml
analyze_transaction : Types.transaction -> string -> bytes option list
                      -> Int64.t option list -> transaction_analysis
analyze_transactions : (...) list -> batch_analysis
format_transaction_analysis / format_batch_analysis
```

`transaction_analysis = { txid; input_analyses; aggregate_stats; critical_findings }`
`batch_analysis = { transactions; total_critical; total_high; total_medium; summary }`

**Nonce analysis** — `lib/analysis/nonce/nonce.mli`:

```ocaml
analyze_input  : string -> int -> Observation.observation list -> input_analysis
analyze_transaction : string -> Observation.observation list list -> input_analysis list
analyze_pair   : observation -> observation -> nonce_relationship
format_result / format_nonce_relationship / format_attack_vector
```

with `risk_level ∈ {"CRITICAL","HIGH","MEDIUM","LOW","NONE"}` and
`risk_score : float` (0.0 safe → 1.0 critical).

**Observations** — `lib/analysis/signature/observation.mli`:

```ocaml
build_observation : Types.transaction -> string -> int -> bytes option
                    -> Int64.t option -> (observation, error) result
build_all : ... -> (int * (observation, error) result) list
```

an `observation` carrying `r`, `s`, `s_form` (`Low_s` | `High_s`), `sighash_type`,
`z : Z.t option`, `ecdsa_valid : bool option`, `public_key : Curve.Point.t option`,
`raw_der_hex`.

**Statistics** — `lib/analysis/statistics/statistics.mli`:
`sig_form_stats`, `sighash_stats`, `z_stats`, `pubkey_stats`, `script_type_stats`,
`ecdsa_stats`, `aggregate_stats`, plus `format_stats` and `stats_to_json`.

**Bitcoin layer** — `lib/bitcoin/`: `Tx_parser.of_hex`, `Types.transaction`,
`Script.Parser`, `Classify.script_type` (P2PKH, P2PK, P2SH, P2WPKH, P2WSH, P2TR,
OP_RETURN, Unknown), `Legacy.compute`, `Bip143.compute`,
`Signature_extraction.extract` / `extract_single`.

**Crypto layer** — `lib/crypto/`: `Der.of_bytes` / `of_hex` (strict DER),
`Signature`, `Verify.verify` / `verify_bytes`, `Curve.Point`, `Field`, `Scalar`,
`Hash`, `Ripemd160`, `Hex`, `Bytes_util`.

**Standalone tools** — `tools/dump_rsz.ml` (`<input_dir> <output.csv>`, writes one
CSV row per signature), `tools/scan_dir.ml` (`<input_dir> <intermediate.csv>`).

**Governance checks** — `tools/check-layering.ps1` (layer discipline),
`tools/check-no-truncation.mjs` (no value may be elided in the UI).

**HTTP API** — `lib/api/endpoints.ml`, 14 routes, listed live by `GET /api/surface`.

### 0.3 Two facts that constrain every layout decision

1. **`lib/api/registry.ml` already answers "search for every function."** It
   parses the project's `.mli` files and returns every `val`, `type`, `module`
   and `include`, with the doc comment attached and the source file and line
   number. The brief's first mandate is implemented as a *mechanism* in this
   repository. Any UI that lists capabilities should read from it rather than
   hard-code a list that will drift.
2. **`nonce.mli` documents its own limits, and they matter for the UI.** HNP
   lattice construction, LLL/BKZ reduction and bit-similarity metrics are
   **not implemented**; `detect_hnp_attack` and `detect_lattice_attack` always
   return `[]`, and the interface states that bit similarity between `r` values
   is cryptographically meaningless — exact equality is the only real
   relationship. So this console offers **no HNP panel, no lattice panel and no
   bit-bias chart**. Those screens would display fabricated analysis. The
   `HNP_partial` and `Lattice_candidate` constructors exist in the type and are
   never produced by the implementation; the UI must render them as
   "not implemented" if they ever appear, not as findings.

---

## 1. Function → UI mapping

### 1.1 Runner commands ✅

| Capability | Source | Intent | Trigger | Inputs | Streaming | Success | Edge case | Priority |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `dune build` | `bin/dune` | prove the tree compiles | Run | none | stream, usually silent | exit 0 + explicit "silent pass" note | non-zero exit, code translated | Primary |
| `dune build @check` | `bin/dune` | type-check everything | Run | none | stream | exit 0 | ⚠ amber warning: three `bin/*.ml` files do not compile | Primary |
| `dune runtest --force` | `test/**/dune` | run all suites | Run | none | stream | exit 0 | exit 1 explained as a missing DLL, not failed assertions | Primary |
| `dune runtest <scope> --force` | `test/**/dune` | run one subtree | Run | `scope` (choice) | stream | exit 0 | invalid scope refused with the allowed list | Primary |
| `dune build @fmt` | `.ocamlformat` | detect format drift | Run | none | stream diff | exit 0 | drift printed in full | Secondary |
| `dune fmt` | `.ocamlformat` | apply formatting | Run | none | stream | exit 0 | mutates the tree; stated before you press Run | Secondary |
| `pwsh -File tools/check-layering.ps1` | `tools/` | enforce layer discipline | Run | none | stream | "LAYERING CHECK PASSED" | violations listed with the offending dune file | Primary |
| `node tools/check-no-truncation.mjs` | `tools/` | enforce "no value is elided" | Run | none | stream | "PASS: no truncation patterns found" | each finding printed with file, line and reason | Primary |
| `dune exec bin/main.exe` | `lib/application/repl.ml` | test a nonce for reuse | Run | transactions → **stdin** | stream | "Nonce is unique." | `0xC0000135` here; notes the REPL has no command verbs | Secondary |
| `dune exec tools/dump_rsz.exe <dir> <csv>` | `tools/dump_rsz.ml` | build an r,s,z dataset | Run | `dir`, `out` (repo paths) | stream, progress every 500 files | CSV written | `0xC0000135` here; SegWit rows leave z empty by design | Primary |
| `dune exec tools/scan_dir.exe <dir> <csv>` | `tools/scan_dir.ml` | parse a directory | Run | `dir`, `out` | stream | intermediate CSV | same DLL issue | Secondary |
| `dune exec <binary> [arg]` | `bin/dune` | drive a standalone tool | Run | `target` (choice), `hex` | stream | tool output | five of six cannot start here | Secondary |
| `dune --version` | — | diagnose the toolchain | Run | none | stream | version | — | Advanced |

### 1.3 Engine routes ⛔ blocked at the process level

All 14 routes in `lib/api/endpoints.ml` are real code, listed live by
`/api/surface`: `health`, `functions`, `parse`, `script/classify`, `script/parse`,
`der/parse`, `sighash/legacy`, `sighash/bip143`, `signatures/extract`,
`observation/build`, `nonce/analyze`, `statistics`, `sig-analysis`, `pipeline`.

They are not reachable because `bin/server.exe` cannot start on this host — it
aborts with `0xC0000135` before binding, for the same missing `cyggmp` that stops
the tools. The console therefore surfaces them as **source truth, not a live
service**, read from the file at request time. No form posts to them.

If that is fixed, the mapping is: `parse` → transaction inspector, `der/parse` →
DER panel, `nonce/analyze` → findings list with `risk_level` chips,
`statistics` → distribution panels, `pipeline` → the whole chain. None of it is
specified further here, because a form bound to a dead endpoint fails on first
submit and proves nothing.

---

## 2. Layout (as built) ✅

```
Top bar (sticky 64px)   ◆ ecdsa-ocaml · operator console   [Clear]  ● runner ready
────────────────────────────────────────────────────────────────────────────────
Sidebar 260px,<lg hidden │  Command detail: title, summary, argument fields,
  Verify: build, check,  │                   [ Run ] or [ ■ Stop ]
  tests, one subtree,    │  ────────────────────────────────────────────────
  fmt, layering guard,   │  Output: $ dune build @check
  truncation guard       │          (streamed bytes, monospace, full)
  Tools: dump_rsz,       │  ────────────────────────────────────────────────
  scan_dir, run binary,  │  exit 0 · 1.3 s — Dune is silent on a clean build
  diagnose               │
  Console: nonce REPL    │
```

Deliberate omissions, each for a reason: no right inspector (no per-selection
payload exists), no separate bottom console (output *is* the result — splitting
it would duplicate one stream), no tabs or routing (one surface, so nothing to
link to), no multi-session indicator (the runner executes one command at a time).

Responsive: below `lg` the sidebar becomes a `<select>`; below 390px the layout
stays single column with no horizontal overflow.

---

## 3. Components (as built) ✅

**`Console`** (`components/console.tsx`) — holds `selectedId` and per-command
argument drafts, so switching commands does not lose typed input. States: idle
(instructions), running (skeleton until first byte, pulsing chip, Stop),
done (exit footer), error (inline banner).

**`CommandDetail`** — renders one catalog entry. Run stays disabled while a
required argument is empty and *names* what is missing beside the button.

**`ArgField`** — `choice` → `<select>` with options printed verbatim;
`hex` → monospace input checked server-side against a pattern; `lines` →
textarea labelled as stdin delivery; `text` → a positional argv entry.

**`OutputConsole`** — header, argv echo, known-issue strip, stream body, exit
footer. Two honesty affordances: an `exit 0` with no output renders an explicit
note that Dune's silence is the pass signal, and `0xC0000135` renders as "a
shared library is missing", not "the tests failed".

**`useRun`** (`lib/commands/useRun.ts`) — consumes the SSE stream, buffers a tail
so an event split across chunks still parses, and exposes `stop`/`reset`.

---

## 4. Real-time design (as built) ✅

| Event | Producer | UI effect |
| --- | --- | --- |
| `meta` | runner, pre-spawn | argv echo appears; known-issue strip renders from the catalog |
| `stdout` | child process | appended to the `aria-live` region, monospace, wrapped |
| `stderr` | child process | appended in the danger tone, in stream order — not a separate pane |
| `exit` | child process | footer shows code, meaning and elapsed; Stop reverts to Run |

Progress is the stream plus an elapsed timer; a compiler reports no percentage,
so inventing one would be a lie. Stop occupies Run's exact position, so the
muscle memory is the same, and it terminates the whole process tree. Reconnect is
not implemented: re-POSTing would re-run the command, which is worse than
reporting that the run ended.

---

## 5. Result presentation ✅

Text, rendered as written, in full — `pre`, monospace, `tabular-nums`, preserving
stdout/stderr ordering. There is deliberately no pretty-printed JSON view of
compiler output: it would destroy the column carets that are the reason to read
it.

**The no-truncation rule is enforced, not aspirational.** `tools/check-no-truncation.mjs`
fails the build on ellipsis overflow, a hidden vertical cap, slicing result data,
or a truncate helper. Running it against this UI found four violations in my own
code; all four are fixed and the check now passes.

Buffer ceiling: the runner holds at most 8,000,000 characters of one stream in
the browser. That is a memory guard, not display clipping. On reaching it the
console says so and tells the operator to re-run in a terminal — the tail is
never quietly dropped.

---

## 6. Visual system (as built) ✅

Tokens in `web/src/app/globals.css` under `@theme`, one source of truth.

| Role | Token | Value |
| --- | --- | --- |
| Canvas / Surface / Raised | `--color-canvas` … | `#0b0e14` / `#12161f` / `#1a2030` |
| Border | `--color-line` / `-soft` | `#2a3245` / `#212838` |
| Ink | `--color-ink` / `-dim` / `-faint` | `#e8ecf4` / `#8b95a8` / `#5a6577` |
| Code | `--color-code` | `#a5b4c8` |
| Accent | `--color-accent` | `#f7931a` |
| Success / Warn / Danger / Info | `--color-ok` … | `#00c853` / `#ffb300` / `#ff3d57` / `#00d4ff` |

Neutrals plus one accent; green, amber, red and cyan appear only as status
semantics. Geist for UI, Geist Mono for hex/DER/exit codes/durations, with
`tabular-nums` so figures do not reflow. Concentric radii (14/10/8/6 px). One
motion curve, two durations (150–160 ms), only `transform`/`opacity`, fully
disabled under `prefers-reduced-motion`. Icons from `lucide-react`.

---

## 7. Edge cases (as built) ✅

| Case | Surface |
| --- | --- |
| Non-zero exit | footer names the code and its meaning |
| `0xC0000135` | "a shared library is missing — for the Zarith tools that is cyggmp" |
| Silent successful build | green note: Dune's silence is the pass signal |
| Timeout | stderr names the limit; process tree terminated |
| Unknown command id | 400, "not a runnable command" |
| Path escape | 400, "resolves outside the repository" |
| Missing / extra argument | 400, naming the argument |
| Buffer ceiling reached | stated inline; no silent drop |
| Runner unreachable | red banner in the output panel |
| Cannot succeed here | amber strip shown before you press Run |

---

## 8. What is not built, and why

| Brief item | Verdict |
| --- | --- |
| Session management, environment inspector | ⛔ no session model |
| File tree, editor, tabs, evaluate-selection | ⛔ no file API, no evaluator endpoint |
| WebSocket streaming | ⛔ no WS support; SSE is used where streaming is real |
| HNP / lattice / bit-bias panels | ⛔ the implementation returns `[]` and the interface says so |
| `value_kind` viewer | ⛔ the type does not exist |
| Forms for the 14 routes | ⛔ the server that serves them cannot start here |
| Right inspector, bottom console, tabs | ⛔ no payload to inspect, no second stream |
| Multi-session concurrency | ⛔ the runner runs one command at a time |

Two decisions would unlock most ⛔ rows, and neither is design work: make
`bin/server.exe` start (put the cygwin `bin` on `PATH`, or link Zarith
statically), and decide whether the engine should grow a session/execution model.
Until then this console does what works and says plainly what it is not.
