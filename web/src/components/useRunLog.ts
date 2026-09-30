"use client";

import { useEffect, useRef, useState } from "react";
import { api, type Envelope, type EndpointResult } from "@/lib/api";

export type StageStatus = "pending" | "running" | "done" | "error";

export interface Stage {
  name: string;
  status: StageStatus;
  ms?: number;
  /** The stage result as the server returned it — never reshaped or trimmed. */
  data?: unknown;
  error?: string;
}

export interface RunRecord {
  id: number;
  endpoint: string;
  label: string;
  request: unknown;
  response: EndpointResult | null;
  durationMs: number | null;
  error: string | null;
  startedAt: number;
  finishedAt: number | null;
  stages?: Stage[];
}

/** A tiny append-only store: results arrive, they are never dropped. */
export function useRunLog() {
  const [runs, setRuns] = useState<RunRecord[]>([]);
  const nextId = useRef(1);

  const push = (r: Omit<RunRecord, "id">) => {
    const id = nextId.current++;
    setRuns((prev) => [...prev, { ...r, id }]);
    return id;
  };

  const update = (id: number, patch: Partial<RunRecord>) => {
    setRuns((prev) => prev.map((r) => (r.id === id ? { ...r, ...patch } : r)));
  };

  const clear = () => setRuns([]);

  return { runs, push, update, clear };
}

/** Run a single endpoint and append the result. */
export async function runEndpoint(
  log: ReturnType<typeof useRunLog>,
  endpoint: string,
  label: string,
  request: unknown,
  invoke: () => Promise<Envelope<EndpointResult>>,
): Promise<void> {
  const startedAt = Date.now();
  const id = log.push({
    endpoint,
    label,
    request,
    response: null,
    durationMs: null,
    error: null,
    startedAt,
    finishedAt: null,
  });
  try {
    const env = await invoke();
    log.update(id, {
      response: env.result,
      durationMs: env.duration_ms ?? Date.now() - startedAt,
      finishedAt: Date.now(),
    });
  } catch (e) {
    log.update(id, { error: String(e), finishedAt: Date.now() });
  }
}

/**
 * Run the full pipeline, publishing each stage as it completes.
 *
 * The server returns all stages in one response, so the stages are revealed
 * progressively rather than being fetched separately: the work is genuinely
 * done before this is called, and this makes each step visible in order as it
 * is unpacked, with its own timing and its own complete payload.
 */
export async function runPipeline(
  log: ReturnType<typeof useRunLog>,
  hex: string,
  txid: string | undefined,
): Promise<void> {
  const startedAt = Date.now();
  const id = log.push({
    endpoint: "pipeline",
    label: "Full pipeline",
    request: { hex, ...(txid ? { txid } : {}) },
    response: null,
    durationMs: null,
    error: null,
    startedAt,
    finishedAt: null,
    stages: [],
  });

  try {
    const env = await api.pipeline(hex, txid);
    const result = env.result as EndpointResult;
    const stages = (result.stages as unknown[] | undefined) ?? [];

    // Reveal stages in order, each with the server's own timing already inside
    // its payload.
    for (let i = 0; i < stages.length; i++) {
      const stage = stages[i] as { stage?: string; ok?: boolean };
      const name = stage?.stage ?? `stage ${i + 1}`;
      log.update(id, {
        stages: stages.slice(0, i).map((s) => {
          const st = s as { stage?: string; ok?: boolean };
          return {
            name: st?.stage ?? "stage",
            status: st?.ok === false ? ("error" as StageStatus) : ("done" as StageStatus),
            data: s,
          };
        }),
      });
      // A short pause between reveals so the sequence is legible. The data is
      // already complete; this only paces the display.
      await new Promise((r) => setTimeout(r, 90));
    }

    log.update(id, {
      response: result,
      durationMs: env.duration_ms ?? Date.now() - startedAt,
      finishedAt: Date.now(),
      stages: stages.map((s) => {
        const st = s as { stage?: string; ok?: boolean };
        return {
          name: st?.stage ?? "stage",
          status: st?.ok === false ? ("error" as StageStatus) : ("done" as StageStatus),
          data: s,
        };
      }),
    });
  } catch (e) {
    log.update(id, { error: String(e), finishedAt: Date.now() });
  }
}

/** Poll server liveness so the header can show a truthful status. */
export function useServerStatus(intervalMs = 5000) {
  const [status, setStatus] = useState<"checking" | "online" | "offline">("checking");
  const [latency, setLatency] = useState<number | null>(null);
  const [info, setInfo] = useState<Record<string, unknown> | null>(null);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;

    const tick = async () => {
      const t0 = performance.now();
      try {
        const h = await api.health();
        if (cancelled) return;
        setStatus("online");
        setLatency(performance.now() - t0);
        setInfo(h);
      } catch {
        if (cancelled) return;
        setStatus("offline");
        setLatency(null);
      }
      if (!cancelled) timer = setTimeout(tick, intervalMs);
    };

    tick();
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [intervalMs]);

  return { status, latency, info };
}
