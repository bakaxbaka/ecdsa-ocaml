# Operator console

A single-page console that drives this repository's OCaml toolchain: it compiles,
type-checks, tests and formats the project by running real commands, and streams
each process's output as it is written.

It is not a dashboard over fabricated data. Every line on screen came out of a
process that actually ran. If the runner is unreachable, or a command fails, the
console says so.

```
┌──────────────────────────────────────────────────────────────┐
│  ecdsa-ocaml   operator console          runner ready        │
├───────────────┬──────────────────────────────────────────────┤
│  Verify       │  Run every test                              │
│   Build       │  ┌────────────────────────────────────────┐  │
│   Type-check  │  │ dune runtest --force                   │  │
│   Run every…  │  ├────────────────────────────────────────┤  │
│   Run one…    │  │ (streamed stdout / stderr)             │  │
│   Check fmt   │  │                                        │  │
│   Apply fmt   │  └────────────────────────────────────────┘  │
│  Tools        │  ┌────────────────────────────────────────┐  │
│   Run binary  │  │ exit 0 · 1.2 s                         │  │
│   Diagnose    │  └────────────────────────────────────────┘  │
│  Console      │                                              │
│   Nonce REPL  │                                              │
└───────────────┴──────────────────────────────────────────────┘
```

## Running it

```powershell
cd web
npm install          # first time only
npm run dev          # http://localhost:3000
```

`npm run build && npm start` serves the production build.

## How a command runs

1. The browser posts `{ commandId, values }` to `/api/run`.
2. `src/lib/commands/catalog.ts` looks the id up. An id that is not in the
   catalog is refused — the console has no free-form command box by design.
3. `src/lib/commands/runner.ts` validates each value against its declared kind
   and builds an argv array from the *catalog*, never from the request body.
4. The process is spawned with `shell: false`, so nothing the user typed is ever
   interpreted as shell syntax. `;`, `|` and `&&` are inert characters.
5. stdout and stderr stream back over server-sent events; the response ends with
   one `exit` event carrying the exit code and elapsed time.

### Constraints that are enforced, not documented

| Concern | How it is handled |
| --- | --- |
| Arbitrary command execution | Only ids in the catalog run. No shell is ever involved. |
| Chaining a second command | Arguments are validated against a per-kind pattern; free text never reaches the argv. |
| Path traversal | `repo-path` arguments must resolve inside the repository root. |
| Argument injection | A value is always its own argv entry; it is never concatenated into a command string. |
| Runaway output | Output is capped at 4 MiB per run. |
| Hung process | Each command has a timeout; on expiry the whole process tree is terminated. |
| Unknown extra fields | A request carrying an undeclared argument is rejected. |

`opam exec` is deliberately not used anywhere: on this machine it aborts with a
cygwin `Exec format error` before reaching the project. `dune` is on `PATH` and
works, so the argv starts with `dune` directly.

## What this host can and cannot run

Measured here, not assumed:

| Command | State |
| --- | --- |
| `dune build` | passes, exit 0, and prints **nothing** — silence is the pass signal |
| `dune build @check` | **fails**: `bin/analyse_txs.ml`, `bin/analyze_nonce_attacks.ml` and `bin/compare_txs.ml` do not compile |
| `dune runtest test/unit/crypto` | passes, exit 0 |
| `dune runtest` (everything) | exit 1 — two suites link Zarith and abort with `0xC0000135` (`STATUS_DLL_NOT_FOUND`), because `cyggmp` is not on this host's `PATH` |
| `dune build @fmt` | passes, no drift |
| `bin/compare_txs.exe` | runs, prints "This binary is under construction", exit 0 |
| `bin/main.exe`, `bin/extract_vectors.exe`, `bin/analyze_nonce_attacks.exe`, `bin/analyse_txs.exe`, `bin/test_nonce_attacks.exe` | abort with `0xC0000135` before reading any input, for the same missing-DLL reason |

Commands that cannot fully succeed here carry a visible warning in the UI before
you run them, and the exit code is translated into its meaning — `0xC0000135`
is reported as a missing shared library, not as "the tests failed".

## Threat model — read before exposing this

`/api/run` executes processes on this repository. **It has no authentication.**

- Bind it to loopback. Do not put it on a network interface, and do not port-
  forward it, without adding authentication and an origin check first.
- The catalog is the security boundary. Adding an entry is adding a capability;
  treat that diff accordingly.
- Prefer enumerated `choice` arguments over `text`. `text` values go to stdin,
  never to the argv, precisely because they are the least constrained kind.

## Layout

```
web/src/
  app/
    layout.tsx          root layout, fonts, metadata
    globals.css         design tokens (@theme), base layer, motion
    page.tsx            mounts the console
    api/run/route.ts    the execution endpoint (SSE)
  components/
    console.tsx         the whole console surface
  lib/
    cn.ts               class merge, exit-code translation, duration format
    commands/
      catalog.ts        every runnable command and its argument schema
      runner.ts         validation, argv construction, spawn, stream
      useRun.ts         client hook that consumes the SSE stream
```

## Design notes

- One accent (`#f7931a`) for primary actions only. Green, amber and red appear
  solely as status semantics.
- Monospace with `tabular-nums` for anything data-bearing — hex, DER, exit
  codes, durations — so figures do not reflow as they update.
- Metric and output text uses `text-wrap: balance` / `pretty`; only `transform`
  and `opacity` are animated; `prefers-reduced-motion` disables motion.
- Loading, empty, silent-success and failure states are all designed. A command
  that prints nothing is explicitly reported as a pass, because Dune's silence is
  otherwise indistinguishable from a stall.
