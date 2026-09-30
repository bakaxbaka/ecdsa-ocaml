# Parked: the command-runner console

This folder is **not built**. It is kept because it works, and because throwing it
away would destroy something that was expensive to get right.

## What it is

An alternative console that drives the repository's own toolchain: it compiles,
type-checks, tests and formats the project by spawning real commands and
streaming their output. It reaches the twenty-odd capabilities the engine exposes
as *source* — `dune build`, `dune runtest`, `dump_rsz`, `scan_dir`, the layering
guard, the no-truncation guard — which the analysis console cannot, because those
are processes rather than HTTP endpoints.

## Why it is parked rather than wired up

It needs a **live Node process** to spawn anything. The app at `web/src` is a
static export that `bin/server.ml` serves from `web/out`; a static folder cannot
execute a process. The two therefore cannot be one Next app:

| | `web/src` (active) | `web/runner-console` (parked) |
| --- | --- | --- |
| Mode | `output: "export"` | server mode |
| Served by | `bin/server.ml` on :8787 | its own `next start` |
| Talks to | `/api/*` on the engine, same origin | `/api/run` in its own process |
| Can run commands | no | yes |

Wiring it up means giving it its own `next.config.ts`, its own `package.json`
scripts, and a deliberate decision about the fact that `/api/run` executes
commands on this repository **with no authentication**. That decision is the
owner's, not mine.

## What is here

```
runner-console/
  console.tsx              the whole surface: command list, arg form, live output
  lib/commands/catalog.ts  every runnable command and its argument schema
  lib/commands/runner.ts   validation, argv construction, spawn, SSE stream
  lib/commands/useRun.ts   the client hook that consumes the stream
  lib/cn.ts                class merge, exit-code meaning, duration formatting
  app/api/run/route.ts     the execution endpoint (SSE)
  app/api/surface/route.ts the capability listing, read from the source
```

Its security model is in the header comment of `lib/commands/runner.ts` and is
worth reading before enabling it: no shell is ever used (`shell: false`), argv is
built from the catalog rather than from the request, free text goes to stdin
instead of the command line, path arguments must resolve inside the repository,
and an unlisted command id is refused outright.

## To revive it

1. Give the folder its own `next.config.ts` and `tsconfig.json`, and a
   `package.json` with `"dev": "next dev runner-console"`.
2. Remove `runner-console` from the exclusions in `../tsconfig.json` and
   `../eslint.config.mjs`.
3. Decide how it is protected. It is a shell; a shell with no auth belongs on
   loopback only.
