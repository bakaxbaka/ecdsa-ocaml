"use client";

import { useCallback, useRef, useState } from "react";

import { COMMAND_BY_ID, type CommandSpec } from "./catalog";

export type LineKind = "stdout" | "stderr" | "note";

export interface OutputLine {
  id: number;
  kind: LineKind;
  text: string;
}

export interface RunState {
  status: "idle" | "running" | "done";
  commandId: string | null;
  spec: CommandSpec | null;
  argv: string[];
  cwd: string;
  knownIssue?: string;
  lines: OutputLine[];
  exit: { code: number | null; signal: string | null; ms: number } | null;
  error: string | null;
}

const EMPTY: RunState = {
  status: "idle",
  commandId: null,
  spec: null,
  argv: [],
  cwd: "",
  lines: [],
  exit: null,
  error: null,
};

/** Server-sent events arrive in chunks that may split mid-line; keep a tail. */
interface ServerChunk {
  kind: "meta" | "stdout" | "stderr" | "exit";
  argv?: string[];
  cwd?: string;
  knownIssue?: string;
  text?: string;
  code?: number | null;
  signal?: string | null;
  ms?: number;
}

export function useRun() {
  const [state, setState] = useState<RunState>(EMPTY);
  const abortRef = useRef<AbortController | null>(null);
  const lineId = useRef(0);

  const stop = useCallback(() => {
    abortRef.current?.abort();
    abortRef.current = null;
    setState((s) => (s.status === "running" ? { ...s, status: "done" } : s));
  }, []);

  const reset = useCallback(() => {
    abortRef.current?.abort();
    abortRef.current = null;
    setState(EMPTY);
  }, []);

  const run = useCallback(async (commandId: string, values: Record<string, unknown>) => {
    const spec = COMMAND_BY_ID.get(commandId);
    if (!spec) {
      setState({ ...EMPTY, error: `"${commandId}" is not a runnable command.` });
      return;
    }

    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    lineId.current = 0;

    setState({
      ...EMPTY,
      status: "running",
      commandId,
      spec,
      argv: [],
    });

    const append = (kind: LineKind, text: string) => {
      setState((s) => {
        const lines = text.split("\n");
        // A trailing newline yields an empty final element; keep it so partial
        // lines join correctly across chunks.
        return {
          ...s,
          lines: [
            ...s.lines,
            ...lines.map((t) => ({ id: lineId.current++, kind, text: t })),
          ],
        };
      });
    };

    try {
      const response = await fetch("/api/run", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ commandId, values }),
        signal: controller.signal,
      });

      if (!response.ok) {
        const payload = (await response.json().catch(() => null)) as
          | { message?: string }
          | null;
        setState((s) => ({
          ...s,
          status: "done",
          error: payload?.message ?? `The runner answered ${response.status}.`,
        }));
        return;
      }

      if (!response.body) {
        setState((s) => ({ ...s, status: "done", error: "The runner sent no stream." }));
        return;
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        let boundary = buffer.indexOf("\n\n");
        while (boundary !== -1) {
          const frame = buffer.slice(0, boundary);
          buffer = buffer.slice(boundary + 2);
          boundary = buffer.indexOf("\n\n");

          const dataLine = frame.split("\n").find((l) => l.startsWith("data: "));
          if (!dataLine) continue;

          let chunk: ServerChunk;
          try {
            // Strip the SSE "data: " protocol prefix, not result data: the payload
          // after it is parsed and rendered in full, never shortened.
          // no-truncation-check-allow
          chunk = JSON.parse(dataLine.slice(6)) as ServerChunk;
          } catch {
            continue;
          }

          if (chunk.kind === "meta") {
            setState((s) => ({
              ...s,
              argv: chunk.argv ?? [],
              cwd: chunk.cwd ?? "",
              knownIssue: chunk.knownIssue,
            }));
          } else if (chunk.kind === "stdout") {
            append("stdout", chunk.text ?? "");
          } else if (chunk.kind === "stderr") {
            append("stderr", chunk.text ?? "");
          } else if (chunk.kind === "exit") {
            setState((s) => ({
              ...s,
              status: "done",
              exit: {
                code: chunk.code ?? null,
                signal: chunk.signal ?? null,
                ms: chunk.ms ?? 0,
              },
            }));
          }
        }
      }

      setState((s) => (s.status === "running" ? { ...s, status: "done" } : s));
    } catch (err) {
      if (controller.signal.aborted) {
        setState((s) => ({ ...s, status: "done" }));
        return;
      }
      setState((s) => ({
        ...s,
        status: "done",
        error:
          err instanceof Error
            ? err.message
            : "The console could not reach its own runner.",
      }));
    } finally {
      abortRef.current = null;
    }
  }, []);

  return { state, run, stop, reset };
}
