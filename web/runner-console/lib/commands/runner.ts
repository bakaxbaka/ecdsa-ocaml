/**
 * Command runner.
 *
 * Executes one catalog entry per request. Four invariants hold for every run:
 *
 *  1. `spawn` is called with an argv array and `shell: false`. Nothing the user
 *     types is ever interpreted by a shell, so `;`, `|`, `&&` and backticks
 *     cannot chain a second command.
 *  2. The argv is built from the catalog spec, not from the request body. The
 *     body supplies only argument *values*, and each value is checked against
 *     its declared kind before it reaches the argv. Free text is never placed on
 *     the argv — it goes to stdin.
 *  3. `cwd` is the repository root, found by walking up for `dune-project`.
 *     Path-valued arguments must resolve inside that root.
 *  4. Output streams. A build or a full test run takes minutes and must show
 *     progress rather than block until exit.
 *
 * `opam exec` is deliberately not used: on this host it aborts with a cygwin
 * "Exec format error" before reaching the project. `dune` is on PATH and works,
 * so the argv starts with `dune` directly.
 */

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import path from "node:path";
import fs from "node:fs";

import { COMMAND_BY_ID, type CommandSpec } from "./catalog";

/* ------------------------------------------------------------------ repo root */

let cachedRoot: string | null = null;

export function repoRoot(): string {
  if (cachedRoot) return cachedRoot;
  let dir = process.cwd();
  for (let i = 0; i < 8; i += 1) {
    if (fs.existsSync(path.join(dir, "dune-project"))) {
      cachedRoot = dir;
      return dir;
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error(
    `No dune-project file was found above ${process.cwd()}. The console has to run from inside the repository.`,
  );
}

/* ------------------------------------------------------------------ validation */

export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ValidationError";
  }
}

function resolveInsideRoot(value: string): string {
  const root = repoRoot();
  const candidate = path.resolve(root, value);
  const rel = path.relative(root, candidate);
  if (rel.startsWith("..") || path.isAbsolute(rel)) {
    throw new ValidationError(
      `"${value}" resolves outside the repository. Only paths inside the project are accepted.`,
    );
  }
  return candidate;
}

/** Upper bound on a single free-text argument, so a paste cannot exhaust memory. */
const MAX_TEXT = 200_000;

function validateValue(
  spec: CommandSpec,
  argName: string,
  raw: unknown,
): string {
  const arg = spec.args.find((a) => a.name === argName);
  if (!arg) {
    throw new ValidationError(`"${spec.id}" has no argument named "${argName}".`);
  }
  if (typeof raw !== "string") {
    throw new ValidationError(`Argument "${argName}" must be a string.`);
  }
  const value = raw.trim();
  if (value === "") {
    if (arg.required) throw new ValidationError(`Argument "${argName}" is required.`);
    return "";
  }

  switch (arg.kind) {
    case "hex":
      if (!arg.pattern || !arg.pattern.test(value)) {
        throw new ValidationError(
          `Argument "${argName}" must be hexadecimal, with no separators.`,
        );
      }
      return value;
    case "integer":
      if (!/^\d+$/.test(value)) {
        throw new ValidationError(`Argument "${argName}" must be a whole number.`);
      }
      return value;
    case "choice":
      if (!arg.options?.includes(value)) {
        throw new ValidationError(
          `Argument "${argName}" must be one of: ${arg.options?.join(", ")}.`,
        );
      }
      return value;
    case "repo-path":
      resolveInsideRoot(value);
      return value;
    case "lines":
    case "text":
      if (value.length > MAX_TEXT) {
        throw new ValidationError(
          `Argument "${argName}" is too large (limit ${MAX_TEXT} characters).`,
        );
      }
      return value;
    default:
      throw new ValidationError(`Unsupported argument kind for "${argName}".`);
  }
}

/* ------------------------------------------------------------------ invocation */

export interface Invocation {
  argv: string[];
  stdin: string | null;
  cwd: string;
}

export function buildInvocation(
  commandId: string,
  values: Record<string, unknown>,
): { spec: CommandSpec; invocation: Invocation } {
  const spec = COMMAND_BY_ID.get(commandId);
  if (!spec) {
    throw new ValidationError(
      `"${commandId}" is not a runnable command. The console runs only commands from its catalog.`,
    );
  }

  const extra = Object.keys(values).filter((k) => !spec.args.some((a) => a.name === k));
  if (extra.length > 0) {
    throw new ValidationError(`Unexpected argument(s): ${extra.join(", ")}.`);
  }

  const resolved = new Map<string, string>();
  for (const arg of spec.args) {
    const value = validateValue(spec, arg.name, values[arg.name] ?? "");
    if (value === "") continue;
    resolved.set(arg.name, value);
  }

  const argv = spec.overridesArgv
    ? [...spec.overridesArgv]
    : ["dune", ...spec.dune];

  switch (spec.id) {
    case "runtest-scope": {
      argv.push(resolved.get("scope")!, "--force");
      break;
    }
    case "binary": {
      argv.push(resolved.get("target")!);
      // A single positional argument, as its own argv entry. Never concatenated
      // into the target — a space in the value cannot become a second argv word.
      const arg = resolved.get("hex");
      if (arg) argv.push(arg);
      break;
    }
    case "doctor": {
      // `dune --version` needs no extra words; the extra probes are added by the
      // reporter below rather than chained into one argv.
      break;
    }
    default:
      break;
  }

  // Positional arguments, in catalog order, for catalog entries that do not
  // supply a complete argv of their own.
  if (!spec.overridesArgv) {
    for (const arg of spec.args) {
      const value = resolved.get(arg.name);
      if (!value) continue;
      if (arg.stdin) continue;
      argv.push(value);
    }
  }

  let stdin: string | null = null;
  if (spec.id === "repl") {
    const input = resolved.get("input") ?? "";
    stdin = input.endsWith("\n") ? input : `${input}\n`;
  }

  return { spec, invocation: { argv, stdin, cwd: repoRoot() } };
}

/* ------------------------------------------------------------------ streaming */

export type Chunk =
  | { kind: "meta"; argv: string[]; cwd: string; knownIssue?: string }
  | { kind: "stdout"; text: string }
  | { kind: "stderr"; text: string }
  | { kind: "exit"; code: number | null; signal: string | null; ms: number };

/**
 * Buffer ceiling for one run, in characters.
 *
 * This is a memory guard, not a display truncation: `tools/check-no-truncation.mjs`
 * forbids shortening a value for presentation, and nothing here ever shortens a
 * value that is shown. What this bounds is how much text is held in the browser at
 * once, because an unbounded stream from a runaway process is a memory leak. When
 * the ceiling is reached the console says so explicitly and tells the operator to
 * run the command in a terminal; it never silently drops the tail.
 */
const MAX_STREAM_CHARS = 8_000_000;

/**
 * Spawn the command and return an async stream of its output. The stream always
 * ends with exactly one `exit` chunk, whether the process succeeded, failed, or
 * was terminated by the timeout.
 */
export function runStream(
  commandId: string,
  values: Record<string, unknown>,
  signal?: AbortSignal,
): AsyncGenerator<Chunk> {
  const { spec, invocation } = buildInvocation(commandId, values);

  return (async function* stream(): AsyncGenerator<Chunk> {
    yield {
      kind: "meta",
      argv: invocation.argv,
      cwd: invocation.cwd,
      knownIssue: spec.knownIssue,
    };

    const started = Date.now();
    let child: ChildProcessWithoutNullStreams;
    try {
      child = spawn(invocation.argv[0], invocation.argv.slice(1), {
        cwd: invocation.cwd,
        // The load-bearing line: no shell, so no interpretation.
        shell: false,
        windowsHide: true,
        env: { ...process.env, NO_COLOR: "1", TERM: "dumb" },
      });
    } catch (err) {
      yield {
        kind: "stderr",
        text: `Could not start the command: ${err instanceof Error ? err.message : String(err)}\n`,
      };
      yield { kind: "exit", code: null, signal: null, ms: Date.now() - started };
      return;
    }

    // Bridge the event callbacks into an async queue the generator can await.
    const queue: Chunk[] = [];
    let wake: (() => void) | null = null;
    let closed = false;
    let captured = 0;

    const push = (chunk: Chunk) => {
      queue.push(chunk);
      wake?.();
      wake = null;
    };

    const relay = (kind: "stdout" | "stderr") => (buf: Buffer) => {
      if (captured >= MAX_STREAM_CHARS) return;
      const text = buf.toString("utf8");
      const room = MAX_STREAM_CHARS - captured;
      captured += text.length;
      // Cut only at the ceiling, and say so. Never elide for layout.
      const over = text.length > room;
      push({
        kind,
        text: over
          ? `${text.slice(0, room)}\n[the stream reached the ${MAX_STREAM_CHARS}-character buffer ceiling and stopped being captured here. The process is still running. Re-run this command in a terminal to see the remainder in full.]\n`
          : text,
      });
    };

    child.stdout.on("data", relay("stdout"));
    child.stderr.on("data", relay("stderr"));

    const timedOut = { hit: false };
    const timer = setTimeout(() => {
      timedOut.hit = true;
      push({
        kind: "stderr",
        text: `\n[stopped after ${spec.timeoutMs} ms — the process tree was terminated]\n`,
      });
      terminate(child);
    }, spec.timeoutMs);

    const onAbort = () => terminate(child);
    signal?.addEventListener("abort", onAbort);

    child.on("error", (err) => {
      push({ kind: "stderr", text: `Command failed: ${err.message}\n` });
    });

    child.on("close", (code, sig) => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      push({ kind: "exit", code, signal: sig, ms: Date.now() - started });
      closed = true;
      wake?.();
      wake = null;
    });

    if (invocation.stdin !== null) child.stdin.write(invocation.stdin);
    child.stdin.end();

    while (true) {
      while (queue.length > 0) yield queue.shift()!;
      if (closed) {
        // Drain anything pushed between the last shift and `closed`.
        while (queue.length > 0) yield queue.shift()!;
        return;
      }
      await new Promise<void>((resolve) => {
        wake = resolve;
      });
    }
  })();
}

/** Kill the process and its children. */
export function terminate(child: ChildProcessWithoutNullStreams) {
  const pid = child.pid;
  if (pid === undefined) return;
  try {
    if (process.platform === "win32") {
      spawn("taskkill", ["/pid", String(pid), "/t", "/f"], {
        shell: false,
        windowsHide: true,
      });
    } else {
      child.kill("SIGKILL");
    }
  } catch {
    /* already gone */
  }
}
