"use client";

import { useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  CircleDot,
  Hammer,
  Play,
  RotateCcw,
  ShieldCheck,
  Square,
  Terminal,
} from "lucide-react";

import { COMMANDS, GROUPS, type ArgSpec, type CommandSpec } from "@/lib/commands/catalog";
import { useRun } from "@/lib/commands/useRun";
import { cn, explainExit, formatDuration } from "@/lib/cn";

/* ------------------------------------------------------------------ helpers */

const GROUP_ICON = {
  verify: ShieldCheck,
  tools: Hammer,
  console: Terminal,
} as const;

function toneClasses(tone: "ok" | "warn" | "danger") {
  return {
    ok: "text-ok border-ok/30 bg-ok/10",
    warn: "text-warn border-warn/30 bg-warn/10",
    danger: "text-danger border-danger/30 bg-danger/10",
  }[tone];
}

/* ------------------------------------------------------------------ arg field */

function ArgField({
  arg,
  value,
  onChange,
  disabled,
}: {
  arg: ArgSpec;
  value: string;
  onChange: (v: string) => void;
  disabled: boolean;
}) {
  const base =
    "w-full rounded-[8px] border border-line bg-canvas px-3 py-2 text-sm text-ink placeholder:text-ink-faint transition-colors duration-150 hover:border-line focus-visible:outline-none disabled:opacity-50";

  return (
    <label className="flex flex-col gap-1.5">
      <span className="flex items-baseline justify-between gap-3">
        <span className="text-xs font-medium tracking-wide text-ink-dim uppercase">
          {arg.label}
        </span>
        {!arg.required && (
          <span className="text-[11px] text-ink-faint">optional</span>
        )}
      </span>

      {arg.kind === "choice" ? (
        <select
          className={cn(base, "appearance-none")}
          value={value}
          disabled={disabled}
          onChange={(e) => onChange(e.target.value)}
        >
          <option value="">— choose —</option>
          {arg.options?.map((o) => (
            <option key={o} value={o} className="data-mono">
              {o}
            </option>
          ))}
        </select>
      ) : arg.kind === "lines" ? (
        <textarea
          className={cn(base, "data-mono wrap-anywhere min-h-24 resize-y text-xs leading-relaxed")}
          value={value}
          disabled={disabled}
          spellCheck={false}
          placeholder={arg.placeholder}
          onChange={(e) => onChange(e.target.value)}
        />
      ) : (
        <input
          type="text"
          className={cn(base, arg.kind === "text" && arg.name !== "scope" && "data-mono text-xs")}
          value={value}
          disabled={disabled}
          spellCheck={false}
          autoComplete="off"
          placeholder={arg.placeholder}
          onChange={(e) => onChange(e.target.value)}
        />
      )}

      <span className="text-[11px] leading-relaxed text-ink-faint">{arg.help}</span>
      {arg.stdin && (
        <span className="text-[11px] text-info">
          Sent on stdin — never placed on the command line.
        </span>
      )}
    </label>
  );
}

/* ------------------------------------------------------------------ sidebar */

function CommandList({
  selectedId,
  onSelect,
  running,
}: {
  selectedId: string | null;
  onSelect: (id: string) => void;
  running: boolean;
}) {
  return (
    <nav className="flex flex-col gap-6" aria-label="Commands">
      {GROUPS.map((group) => {
        const items = COMMANDS.filter((c) => c.group === group.id);
        if (items.length === 0) return null;
        const Icon = GROUP_ICON[group.id];
        return (
          <div key={group.id} className="flex flex-col gap-1">
            <div className="flex items-center gap-2 px-2 pb-1">
              <Icon className="size-3.5 text-ink-faint" aria-hidden />
              <h2 className="text-[11px] font-semibold tracking-[0.08em] text-ink-faint uppercase">
                {group.label}
              </h2>
              <span className="text-[11px] text-ink-faint/70">{group.blurb}</span>
            </div>
            {items.map((cmd) => {
              const active = cmd.id === selectedId;
              return (
                <button
                  key={cmd.id}
                  type="button"
                  disabled={running}
                  onClick={() => onSelect(cmd.id)}
                  aria-current={active ? "true" : undefined}
                  className={cn(
                    "group flex items-center gap-2 rounded-[8px] px-2.5 py-2 text-left text-sm transition-colors duration-150",
                    active
                      ? "bg-raised text-ink"
                      : "text-ink-dim hover:bg-raised/60 hover:text-ink",
                    running && "opacity-50",
                  )}
                >
                  <ChevronRight
                    className={cn(
                      "size-3.5 shrink-0 transition-transform duration-150",
                      active ? "text-accent" : "text-ink-faint",
                    )}
                    aria-hidden
                  />
                  <span className="flex-1 truncate">{cmd.label}</span>
                  {cmd.knownIssue && (
                    <AlertTriangle
                      className="size-3.5 shrink-0 text-warn"
                      aria-label="Known problem"
                    />
                  )}
                </button>
              );
            })}
          </div>
        );
      })}
    </nav>
  );
}

/* ------------------------------------------------------------------ console */

function OutputConsole({ state }: { state: ReturnType<typeof useRun>["state"] }) {
  const exit = state.exit ? explainExit(state.exit.code, state.exit.signal) : null;

  const body = state.lines.filter((l) => l.text !== "" || l.kind !== "stdout");

  return (
    <section className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-[14px] border border-line-soft bg-surface">
      <header className="flex items-center gap-3 border-b border-line-soft px-4 py-2.5">
        <Terminal className="size-4 text-ink-faint" aria-hidden />
        <h2 className="text-xs font-semibold tracking-[0.08em] text-ink-dim uppercase">
          Output
        </h2>
        <div className="ml-auto flex items-center gap-3 text-xs">
          {state.status === "running" && (
            <span className="flex items-center gap-2 text-accent">
              <span className="size-1.5 animate-pulse rounded-full bg-accent" />
              running
            </span>
          )}
          {state.exit && (
            <span className="num text-ink-faint">{formatDuration(state.exit.ms)}</span>
          )}
        </div>
      </header>

      {state.argv.length > 0 && (
        <div className="data-mono wrap-anywhere border-b border-line-soft bg-canvas px-4 py-2 text-[11px] text-ink-faint">
          <span className="text-ink-faint/60">$ </span>
          <span className="text-code">{state.argv.join(" ")}</span>
        </div>
      )}

      {state.knownIssue && (
        <div className="flex gap-2.5 border-b border-warn/20 bg-warn/5 px-4 py-3">
          <AlertTriangle className="mt-px size-4 shrink-0 text-warn" aria-hidden />
          <p className="text-xs leading-relaxed text-warn/90">{state.knownIssue}</p>
        </div>
      )}

      <div className="min-h-0 flex-1 overflow-auto px-4 py-3">
        {state.error && (
          <p className="mb-3 rounded-[8px] border border-danger/30 bg-danger/10 px-3 py-2 text-xs leading-relaxed text-danger">
            {state.error}
          </p>
        )}

        {state.status === "done" &&
          !state.error &&
          state.exit?.code === 0 &&
          state.lines.every((l) => l.text.trim() === "") && (
            <p className="rounded-[8px] border border-ok/25 bg-ok/5 px-3 py-2 text-xs leading-relaxed text-ok/90">
              The command produced no output. Dune is silent on a clean build, so this
              is the pass signal rather than a stalled run.
            </p>
          )}

        {state.status === "idle" && !state.error && (
          <div className="flex h-full flex-col items-center justify-center gap-2 py-12 text-center">
            <Terminal className="size-6 text-ink-faint/60" aria-hidden />
            <p className="text-sm text-ink-dim">Nothing has run yet.</p>
            <p className="max-w-sm text-xs leading-relaxed text-ink-faint">
              Pick a command on the left, fill in its arguments, and press Run. Output
              streams here exactly as the process writes it.
            </p>
          </div>
        )}

        {state.status === "running" && state.lines.length === 0 && (
          <div className="flex flex-col gap-1.5" aria-live="polite">
            <div className="skeleton h-3 w-2/3 rounded-[4px]" />
            <div className="skeleton h-3 w-1/2 rounded-[4px]" />
            <div className="skeleton h-3 w-3/5 rounded-[4px]" />
          </div>
        )}

        {body.length > 0 && (
          <pre className="data-mono whitespace-pre-wrap text-xs leading-[1.6]" aria-live="polite">
            {body.map((line) => (
              <div
                key={line.id}
                className={cn(
                  "wrap-anywhere",
                  line.kind === "stderr" && "text-danger/90",
                  line.kind === "note" && "text-ink-faint",
                )}
              >
                {line.text === "" ? "\u00a0" : line.text}
              </div>
            ))}
          </pre>
        )}
      </div>

      {exit && (
        <footer
          className={cn(
            "flex items-start gap-2.5 border-t px-4 py-3 text-xs",
            toneClasses(exit.tone),
          )}
        >
          {exit.tone === "ok" ? (
            <CheckCircle2 className="mt-px size-4 shrink-0" aria-hidden />
          ) : (
            <AlertTriangle className="mt-px size-4 shrink-0" aria-hidden />
          )}
          <div className="flex flex-col gap-0.5">
            <span className="font-medium">{exit.label}</span>
            <span className="opacity-80">{exit.detail}</span>
          </div>
        </footer>
      )}
    </section>
  );
}

/* ------------------------------------------------------------------ detail */

function CommandDetail({
  spec,
  values,
  setValue,
  running,
  onRun,
  onStop,
}: {
  spec: CommandSpec;
  values: Record<string, string>;
  setValue: (name: string, v: string) => void;
  running: boolean;
  onRun: () => void;
  onStop: () => void;
}) {
  const missing = spec.args.filter((a) => a.required && !values[a.name]?.trim());

  return (
    <section className="flex flex-col gap-4 rounded-[14px] border border-line-soft bg-surface p-4">
      <div className="flex flex-col gap-1.5">
        <h2 className="text-sm font-semibold text-ink">{spec.label}</h2>
        <p className="max-w-prose text-xs leading-relaxed text-ink-dim">{spec.summary}</p>
      </div>

      {spec.args.length > 0 && (
        <div className="flex flex-col gap-4">
          {spec.args.map((arg) => (
            <ArgField
              key={arg.name}
              arg={arg}
              value={values[arg.name] ?? ""}
              onChange={(v) => setValue(arg.name, v)}
              disabled={running}
            />
          ))}
        </div>
      )}

      <div className="flex items-center gap-2 pt-1">
        {running ? (
          <button
            type="button"
            onClick={onStop}
            className="flex h-11 items-center gap-2 rounded-[8px] border border-line px-4 text-sm font-medium text-ink transition-colors duration-150 hover:border-danger/50 hover:text-danger"
          >
            <Square className="size-4" aria-hidden />
            Stop
          </button>
        ) : (
          <button
            type="button"
            onClick={onRun}
            disabled={missing.length > 0}
            className={cn(
              "flex h-11 items-center gap-2 rounded-[8px] px-4 text-sm font-semibold transition-colors duration-150",
              missing.length > 0
                ? "cursor-not-allowed bg-raised text-ink-faint"
                : "bg-accent text-canvas hover:bg-accent/90",
            )}
          >
            <Play className="size-4" aria-hidden />
            Run
          </button>
        )}
        {missing.length > 0 && !running && (
          <span className="text-xs text-ink-faint">
            Needs {missing.map((a) => a.label).join(", ")}
          </span>
        )}
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ page */

export default function Console() {
  const [selectedId, setSelectedId] = useState<string>(COMMANDS[0].id);
  const [values, setValues] = useState<Record<string, Record<string, string>>>({});
  const { state, run, stop, reset } = useRun();

  const spec = useMemo(
    () => COMMANDS.find((c) => c.id === selectedId) ?? COMMANDS[0],
    [selectedId],
  );

  const current = values[spec.id] ?? {};
  const running = state.status === "running";

  const setValue = (name: string, v: string) =>
    setValues((prev) => ({ ...prev, [spec.id]: { ...prev[spec.id], [name]: v } }));

  const onRun = () => run(spec.id, current);

  return (
    <div className="flex min-h-dvh flex-col">
      <header className="sticky top-0 z-10 flex h-16 items-center gap-4 border-b border-line-soft bg-canvas/95 px-4 backdrop-blur-sm sm:px-6">
        <div className="flex items-center gap-2.5">
          <span className="grid size-7 place-items-center rounded-[6px] bg-accent/15">
            <CircleDot className="size-4 text-accent" aria-hidden />
          </span>
          <div className="flex flex-col leading-none">
            <span className="text-sm font-semibold tracking-tight text-ink">
              ecdsa-ocaml
            </span>
            <span className="text-[11px] text-ink-faint">operator console</span>
          </div>
        </div>

        <div className="ml-auto flex items-center gap-3">
          {state.status !== "idle" && (
            <button
              type="button"
              onClick={reset}
              className="flex h-9 items-center gap-1.5 rounded-[8px] border border-line px-3 text-xs text-ink-dim transition-colors duration-150 hover:border-line hover:text-ink"
            >
              <RotateCcw className="size-3.5" aria-hidden />
              Clear
            </button>
          )}
          <span className="hidden items-center gap-1.5 text-[11px] text-ink-faint sm:flex">
            <span
              className={cn(
                "size-1.5 rounded-full",
                running ? "animate-pulse bg-accent" : "bg-ok",
              )}
            />
            {running ? "process running" : "runner ready"}
          </span>
        </div>
      </header>

      <div className="mx-auto flex w-full max-w-[1600px] flex-1 gap-4 p-4 sm:p-6">
        <aside className="hidden w-64 shrink-0 lg:block">
          <CommandList selectedId={spec.id} onSelect={setSelectedId} running={running} />
        </aside>

        <main className="flex min-w-0 flex-1 flex-col gap-4">
          <div className="lg:hidden">
            <label className="flex flex-col gap-1.5">
              <span className="text-xs font-medium tracking-wide text-ink-dim uppercase">
                Command
              </span>
              <select
                className="h-11 w-full appearance-none rounded-[8px] border border-line bg-canvas px-3 text-sm text-ink"
                value={spec.id}
                disabled={running}
                onChange={(e) => setSelectedId(e.target.value)}
              >
                {COMMANDS.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.label}
                  </option>
                ))}
              </select>
            </label>
          </div>

          <CommandDetail
            spec={spec}
            values={current}
            setValue={setValue}
            running={running}
            onRun={onRun}
            onStop={stop}
          />

          <OutputConsole state={state} />
        </main>
      </div>
    </div>
  );
}
