"use client";

import { useCallback, useMemo, useState } from "react";

import { CatalogueRail } from "@/components/CatalogueRail";
import { ResultPane } from "@/components/ResultPane";
import { Charts } from "@/components/Charts";
import { api, ENDPOINTS, type EndpointId } from "@/lib/api";
import { runEndpoint, runPipeline, useRunLog, useServerStatus } from "@/components/useRunLog";
import { cn } from "@/lib/utils";

/* ------------------------------------------------------------------ inputs */

/** The extra fields an endpoint needs beyond `hex` and `txid`. */
const EXTRA: Record<string, { name: string; label: string; placeholder: string }[]> = {
  scriptClassify: [
    { name: "script_pubkey_hex", label: "scriptPubKey hex", placeholder: "full script hex, e.g. a P2PKH scriptPubKey" },
  ],
  scriptParse: [
    { name: "script_hex", label: "script hex", placeholder: "full script hex" },
  ],
  derParse: [
    { name: "der_hex", label: "DER signature hex", placeholder: "full DER signature with its sighash byte" },
  ],
  sighashLegacy: [
    { name: "input_index", label: "input index", placeholder: "0" },
    { name: "script_code_hex", label: "script code hex", placeholder: "full script code hex" },
    { name: "sighash_type", label: "sighash type", placeholder: "1" },
  ],
  sighashBip143: [
    { name: "input_index", label: "input index", placeholder: "0" },
    { name: "script_code_hex", label: "script code hex", placeholder: "full script code hex" },
    { name: "value", label: "spent value (satoshis)", placeholder: "100000" },
    { name: "sighash_type", label: "sighash type", placeholder: "1" },
  ],
};

const NEEDS_HEX = new Set([
  "parse",
  "extract",
  "sighashLegacy",
  "sighashBip143",
  "observation",
  "nonce",
  "statistics",
  "sigAnalysis",
  "pipeline",
]);

/* ------------------------------------------------------------------ page */

export default function Page() {
  const log = useRunLog();
  const server = useServerStatus();

  const [endpointId, setEndpointId] = useState<EndpointId>("parse");
  const [hex, setHex] = useState("");
  const [txid, setTxid] = useState("");
  const [extra, setExtra] = useState<Record<string, string>>({});
  const [running, setRunning] = useState(false);

  const [showCatalogue, setShowCatalogue] = useState(true);
  const [view, setView] = useState<"results" | "charts">("results");

  const endpoint = useMemo(
    () => ENDPOINTS.find((e) => e.id === endpointId) ?? ENDPOINTS[0],
    [endpointId],
  );

  /** The exact request that will be sent. Rendered and editable, verbatim. */
  const request = useMemo(() => {
    const body: Record<string, unknown> = {};
    if (NEEDS_HEX.has(endpointId)) {
      body.hex = hex;
      if (txid.trim()) body.txid = txid.trim();
    }
    for (const f of EXTRA[endpointId] ?? []) {
      const v = extra[f.name];
      if (v !== undefined && v.trim() !== "") {
        const numeric = f.name === "input_index" || f.name === "sighash_type" || f.name === "value";
        body[f.name] = numeric ? Number(v) : v.trim();
      }
    }
    return body;
  }, [endpointId, hex, txid, extra]);

  const invoke = useCallback(async () => {
    const hexTrim = hex.trim();
    const txidTrim = txid.trim() || undefined;
    switch (endpointId) {
      case "parse":
        return api.parse(hexTrim, txidTrim);
      case "extract":
        return api.extract(hexTrim, txidTrim);
      case "scriptClassify":
        return api.scriptClassify(extra.script_pubkey_hex?.trim() ?? "");
      case "scriptParse":
        return api.scriptParse(extra.script_hex?.trim() ?? "");
      case "derParse":
        return api.derParse(extra.der_hex?.trim() ?? "");
      case "sighashLegacy":
        return api.sighashLegacy(
          hexTrim,
          Number(extra.input_index ?? 0),
          extra.script_code_hex?.trim() ?? "",
          Number(extra.sighash_type ?? 1),
        );
      case "sighashBip143":
        return api.sighashBip143(
          hexTrim,
          Number(extra.input_index ?? 0),
          extra.script_code_hex?.trim() ?? "",
          extra.value?.trim() ?? "0",
          Number(extra.sighash_type ?? 1),
        );
      case "observation":
        return api.observation(hexTrim, txidTrim);
      case "nonce":
        return api.nonce(hexTrim, txidTrim);
      case "statistics":
        return api.statistics(hexTrim, txidTrim);
      case "sigAnalysis":
        return api.sigAnalysis(hexTrim, txidTrim);
      case "pipeline":
        return api.pipeline(hexTrim, txidTrim);
      default:
        throw new Error(`No client for endpoint "${endpointId}".`);
    }
  }, [endpointId, hex, txid, extra]);

  const run = async () => {
    setRunning(true);
    try {
      if (endpointId === "pipeline") {
        await runPipeline(log, hex.trim(), txid.trim() || undefined);
        setView("results");
      } else {
        await runEndpoint(log, endpointId, endpoint.label, request, invoke);
        setView("results");
      }
    } finally {
      setRunning(false);
    }
  };

  const exportAll = () => {
    // The complete run log, every payload, unshortened.
    const blob = new Blob([JSON.stringify(log.runs, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ecdsa-console-runs-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const groups = useMemo(() => {
    const m = new Map<string, typeof ENDPOINTS[number][]>();
    for (const e of ENDPOINTS) {
      const arr = m.get(e.group) ?? [];
      arr.push(e);
      m.set(e.group, arr);
    }
    return [...m.entries()];
  }, []);

  return (
    <div className="grid grid-rows-[auto_1fr] h-screen">
      <header className="flex items-center gap-4 px-4 py-2 border-b border-border bg-panel">
        <div className="flex items-baseline gap-2">
          <h1 className="font-semibold">ecdsa-ocaml analysis console</h1>
        </div>

        <div
          className={cn(
            "flex items-center gap-2 px-2 py-0.5 rounded border text-[11px]",
            server.status === "online"
              ? "border-ok/40 text-ok"
              : server.status === "offline"
                ? "border-danger/50 text-danger"
                : "border-border text-text-dim",
          )}
          title={server.info ? JSON.stringify(server.info) : undefined}
        >
          <span className={cn("num", server.status === "online" && "text-ok")}>
            {server.status}
          </span>
          {server.latency !== null && (
            <span className="num text-text-faint">{server.latency.toFixed(0)} ms</span>
          )}
        </div>

        <nav className="ml-auto flex items-center gap-1">
          <button
            type="button"
            onClick={() => setShowCatalogue((s) => !s)}
            className={cn(
              "px-2.5 py-1 rounded border text-[12px]",
              showCatalogue
                ? "border-accent text-accent bg-highlight"
                : "border-border text-text-dim hover:text-text",
            )}
            aria-pressed={showCatalogue}
          >
            Catalogue
          </button>
          <button
            type="button"
            onClick={() => setView("results")}
            className={cn(
              "px-2.5 py-1 rounded border text-[12px]",
              view === "results"
                ? "border-accent text-accent bg-highlight"
                : "border-border text-text-dim hover:text-text",
            )}
            aria-pressed={view === "results"}
          >
            Results ({log.runs.length})
          </button>
          <button
            type="button"
            onClick={() => setView("charts")}
            className={cn(
              "px-2.5 py-1 rounded border text-[12px]",
              view === "charts"
                ? "border-accent text-accent bg-highlight"
                : "border-border text-text-dim hover:text-text",
            )}
            aria-pressed={view === "charts"}
          >
            Charts
          </button>
          <button
            type="button"
            onClick={exportAll}
            disabled={log.runs.length === 0}
            className="px-2.5 py-1 rounded border border-border text-text-dim hover:text-text text-[12px] disabled:opacity-40"
          >
            Export
          </button>
          <button
            type="button"
            onClick={log.clear}
            disabled={log.runs.length === 0}
            className="px-2.5 py-1 rounded border border-border text-text-dim hover:text-text text-[12px] disabled:opacity-40"
          >
            Clear
          </button>
        </nav>
      </header>

      <div
        className={cn(
          "grid min-h-0",
          showCatalogue ? "grid-cols-[320px_1fr]" : "grid-cols-1",
        )}
      >
        {showCatalogue && (
          <aside className="border-r border-border bg-panel min-h-0 flex flex-col">
            <CatalogueRail
              onUseSignature={({ signature }) => {
                setHex(signature);
                setEndpointId("parse");
              }}
            />
          </aside>
        )}

        <main className="min-h-0 overflow-y-auto p-4">
          <div className="flex flex-col gap-4 max-w-4xl">
            <section className="border border-border rounded bg-panel p-3">
              <div className="flex items-center gap-3 mb-3">
                <h2 className="font-medium">Endpoint</h2>
                <button
                  type="button"
                  onClick={run}
                  disabled={running || server.status === "offline"}
                  className="px-3 py-1 rounded border border-accent text-accent bg-highlight hover:bg-accent/10 disabled:opacity-40"
                >
                  {running ? "Running" : "Run"}
                </button>
                {server.status === "offline" && (
                  <span className="text-danger text-[11px]">
                    The analysis server is not answering. Start it, then this becomes enabled.
                  </span>
                )}
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="col-span-2">
                  <label className="block text-text-dim text-[11px] mb-1" htmlFor="endpoint">
                    Endpoint
                  </label>
                  <select
                    id="endpoint"
                    value={endpointId}
                    onChange={(e) => setEndpointId(e.target.value as EndpointId)}
                    className="w-full bg-bg border border-border rounded px-2 py-1 text-[12px]"
                  >
                    {groups.map(([group, items]) => (
                      <optgroup key={group} label={group}>
                        {items.map((it) => (
                          <option key={it.id} value={it.id}>
                            {it.label}
                          </option>
                        ))}
                      </optgroup>
                    ))}
                  </select>
                  <div className="text-text-faint text-[11px] mt-1">
                    {ENDPOINTS.length} endpoints. The catalogue on the left lists every function the
                    engine exposes, derived from the project’s .mli files.
                  </div>
                </div>

                {NEEDS_HEX.has(endpointId) && (
                  <>
                    <div className="col-span-2">
                      <label className="block text-text-dim text-[11px] mb-1" htmlFor="hex">
                        hex
                      </label>
                      <textarea
                        id="hex"
                        value={hex}
                        onChange={(e) => setHex(e.target.value)}
                        placeholder="raw transaction, hex"
                        spellCheck={false}
                        className="w-full bg-bg border border-border rounded px-2 py-1 text-[12px] placeholder:text-text-faint font-mono resize-y min-h-20"
                      />
                    </div>
                    <div className="col-span-2">
                      <label className="block text-text-dim text-[11px] mb-1" htmlFor="txid">
                        txid (optional)
                      </label>
                      <input
                        id="txid"
                        value={txid}
                        onChange={(e) => setTxid(e.target.value)}
                        placeholder="64 hex characters"
                        spellCheck={false}
                        className="w-full bg-bg border border-border rounded px-2 py-1 text-[12px] placeholder:text-text-faint font-mono"
                      />
                      <div className="text-text-faint text-[11px] mt-1">
                        Required for a SegWit txid. A SegWit transaction’s derived hash is its
                        wtxid, not its txid, and the server says so in <code>id_derivation</code>{" "}
                        rather than mislabelling it.
                      </div>
                    </div>
                  </>
                )}

                {(EXTRA[endpointId] ?? []).map((f) => (
                  <div key={f.name}>
                    <label
                      className="block text-text-dim text-[11px] mb-1"
                      htmlFor={`extra-${f.name}`}
                    >
                      {f.label}
                    </label>
                    <input
                      id={`extra-${f.name}`}
                      value={extra[f.name] ?? ""}
                      onChange={(e) => setExtra((s) => ({ ...s, [f.name]: e.target.value }))}
                      placeholder={f.placeholder}
                      spellCheck={false}
                      className="w-full bg-bg border border-border rounded px-2 py-1 text-[12px] placeholder:text-text-faint font-mono"
                    />
                  </div>
                ))}
              </div>

              {NEEDS_HEX.has(endpointId) && (
                <pre className="data mt-2 p-2 bg-[#0d1014] rounded">
                  {JSON.stringify(request, null, 2)}
                </pre>
              )}
              <div className="text-text-dim text-[11px] leading-relaxed mt-1">
                request JSON (sent verbatim)
              </div>
            </section>

            {view === "charts" ? (
              <Charts runs={log.runs} />
            ) : log.runs.length === 0 ? (
              <section className="border border-border rounded bg-panel p-3 text-text-dim text-[12px]">
                No results yet. Pick an endpoint, paste a transaction, and press Run. Every result
                is kept in full: nothing is dropped, shortened, or summarised away.
              </section>
            ) : (
              log.runs
                .slice()
                .reverse()
                .map((r) => (
                  <div key={r.id} className="flex flex-col gap-2">
                    <div className="flex items-baseline gap-2 text-[11px] text-text-dim">
                      <span className="num text-text-faint">#{r.id}</span>
                      <span className="text-text">{r.label}</span>
                      <span className="text-text-faint">
                        {new Date(r.startedAt).toLocaleTimeString()}
                      </span>
                      {r.durationMs !== null && (
                        <span className="num text-accent ml-auto">
                          {r.durationMs.toFixed(1)} ms
                        </span>
                      )}
                    </div>

                    {r.stages && r.stages.length > 0 && (
                      <ol className="flex flex-col gap-1 border border-border rounded bg-panel p-2">
                        {r.stages.map((s, i) => (
                          <li key={i} className="flex items-center gap-2 text-[11px]">
                            <span
                              className={cn(
                                "w-3",
                                s.status === "done"
                                  ? "text-ok"
                                  : s.status === "error"
                                    ? "text-danger"
                                    : "text-text-faint",
                              )}
                            >
                              {s.status === "done" ? "✓" : s.status === "error" ? "✗" : "○"}
                            </span>
                            <span className="text-text">{s.name}</span>
                          </li>
                        ))}
                      </ol>
                    )}

                    {r.error && (
                      <div className="border border-danger/50 rounded bg-danger/10 p-2 text-danger text-[12px] break-all">
                        {r.error}
                      </div>
                    )}

                    {r.response && (
                      <ResultPane
                        title={r.label}
                        value={r.response}
                        durationMs={r.durationMs ?? undefined}
                      />
                    )}
                  </div>
                ))
            )}
          </div>
        </main>
      </div>
    </div>
  );
}
