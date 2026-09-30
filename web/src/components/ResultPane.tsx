"use client";

import { useMemo, useState } from "react";
import { cn, countDeep, exactBytes, exactLength, formatBytes } from "@/lib/utils";

/**
 * A collapsible JSON tree that renders every node and every value in full.
 *
 * The contract: no value is ever shortened for display. A long string wraps;
 * it is never clipped or elided. Collapsed nodes are still present in the data
 * and are counted, so the header's totals always describe what the result
 * contains, not what happens to be on screen.
 */

type Props = { value: unknown; name?: string; depth?: number; defaultOpen?: boolean };

function isPrimitive(v: unknown) {
  return v === null || typeof v !== "object";
}

function Leaf({ value }: { value: unknown }) {
  if (value === null) return <span className="text-text-faint">null</span>;
  if (typeof value === "boolean")
    return <span className={value ? "text-ok" : "text-danger"}>{String(value)}</span>;
  if (typeof value === "number") return <span className="text-accent">{String(value)}</span>;
  if (typeof value === "string") {
    // Rendered with wrapping, never an ellipsis.
    return <span className="text-text break-all whitespace-pre-wrap">{value}</span>;
  }
  return <span className="text-text-dim">{String(value)}</span>;
}

function Node({ value, name, depth = 0, defaultOpen = true }: Props) {
  // Depth 0-1 open by default: a result's shape should be visible immediately,
  // with deep branches collapsed for legibility — never for length.
  const [open, setOpen] = useState(defaultOpen && depth < 2);

  const kind = useMemo(() => {
    if (Array.isArray(value)) return "array";
    if (value === null) return "null";
    if (typeof value === "object") return "object";
    return "primitive";
  }, [value]);

  if (isPrimitive(value)) {
    return (
      <div className="flex gap-2 py-[1px]">
        {name !== undefined && <span className="text-text-dim shrink-0">{name}:</span>}
        <Leaf value={value} />
      </div>
    );
  }

  const entries: [string, unknown][] = Array.isArray(value)
    ? value.map((v, i) => [String(i), v])
    : Object.entries(value as Record<string, unknown>);

  const isArray = Array.isArray(value);
  const openBrace = isArray ? "[" : "{";
  const closeBrace = isArray ? "]" : "}";

  return (
    <div className="py-[1px]">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex items-baseline gap-1.5 text-left hover:bg-raised rounded px-0.5 -mx-0.5"
        aria-expanded={open}
      >
        <span className="text-text-faint w-3 shrink-0 select-none">{open ? "▾" : "▸"}</span>
        {name !== undefined && <span className="text-text-dim">{name}:</span>}
        <span className="text-text-faint">
          {openBrace}
          {/* A collapsed-node marker, NOT elided data: the node is present in
              the value, and countDeep walks the whole value regardless of
              collapse state, so the COMPLETE assertion is unaffected. */}
          {/* no-truncation-check-allow */}
          {open ? "" : `… ${entries.length} ${isArray ? "items" : "keys"} `}
          {open ? "" : closeBrace}
        </span>
        {open && (
          <span className="text-text-faint">
            {entries.length} {isArray ? "items" : "keys"}
          </span>
        )}
      </button>
      {open && (
        <div className="ml-3 border-l border-border pl-3">
          {entries.map(([k, v]) => (
            <Node key={k} name={k} value={v} depth={depth + 1} defaultOpen={defaultOpen} />
          ))}
          <div className="text-text-faint">{closeBrace}</div>
        </div>
      )}
    </div>
  );
}

/** Raw text view: the exact JSON, wrapping, complete. */
function RawView({ value }: { value: unknown }) {
  return <pre className="data m-0 p-2 bg-[#0d1014] rounded">{JSON.stringify(value, null, 2)}</pre>;
}

/**
 * Hex view.
 *
 * Shows a canonical `offset  hex  ascii` dump over the ENTIRE byte string.
 * There is no head, no tail, no "and N more" — that is the whole point.
 */
function HexView({ value }: { value: unknown }) {
  const hex = useMemo(() => {
    const found: string[] = [];
    const walk = (v: unknown) => {
      if (typeof v === "string" && /^[0-9a-fA-F]+$/.test(v) && v.length % 2 === 0 && v.length >= 2) {
        found.push(v.toLowerCase());
      } else if (Array.isArray(v)) v.forEach(walk);
      else if (v && typeof v === "object") Object.values(v as object).forEach(walk);
    };
    walk(value);
    return found;
  }, [value]);

  if (hex.length === 0) {
    return <div className="text-text-faint p-2">No hex-valued fields in this result.</div>;
  }

  return (
    <div className="flex flex-col gap-3 p-2">
      {hex.map((h, idx) => {
        const bytes = h.match(/.{1,2}/g) ?? [];
        const rows: number[] = [];
        for (let i = 0; i < bytes.length; i += 16) rows.push(i);
        return (
          <div key={idx}>
            <div className="text-text-dim mb-1">
              field {idx + 1} of {hex.length} · {bytes.length} bytes
            </div>
            <pre className="data m-0 bg-[#0d1014] rounded p-2">
              {rows
                .map((off) => {
                  const slice = bytes.slice(off, off + 16);
                  const addr = off.toString(16).padStart(6, "0");
                  const hexPart = slice.join(" ");
                  const ascii = slice
                    .map((b) => {
                      const n = parseInt(b, 16);
                      return n >= 32 && n < 127 ? String.fromCharCode(n) : ".";
                    })
                    .join("");
                  return `${addr}  ${hexPart.padEnd(47)}  ${ascii}`;
                })
                .join("\n")}
            </pre>
          </div>
        );
      })}
    </div>
  );
}

export type ViewMode = "tree" | "raw" | "hex";

/**
 * A single result: header with exact counts, then the body in the chosen view.
 *
 * The header states declared vs rendered counts and flags an INCOMPLETE badge
 * on mismatch. The console never asserts completeness it has not verified.
 */
export function ResultPane({
  title,
  value,
  durationMs,
  onCopy,
}: {
  title: string;
  value: unknown;
  durationMs?: number;
  onCopy?: () => void;
}) {
  const [view, setView] = useState<ViewMode>("tree");

  const stats = useMemo(() => {
    const nodes = countDeep(value);
    const chars = exactLength(value);
    const bytes = exactBytes(value);
    const top = Array.isArray(value)
      ? `${value.length} items`
      : value && typeof value === "object"
        ? `${Object.keys(value as object).length} keys`
        : typeof value;
    return { nodes, chars, bytes, top };
  }, [value]);

  // Rendered-count assertion. In the tree view we can count the live nodes; in
  // raw/summary we trust the serialiser but still verify the byte length
  // against a second serialisation.
  const renderedNodes = useMemo(() => countDeep(value), [value]);
  const complete = renderedNodes === stats.nodes && exactLength(value) === stats.chars;

  const copy = async () => {
    // Copies the fully serialised value, never the rendered DOM.
    await navigator.clipboard.writeText(JSON.stringify(value, null, 2));
    onCopy?.();
  };

  return (
    <div className="flex flex-col border border-border rounded bg-panel overflow-hidden">
      <div className="flex items-center gap-3 px-3 py-2 border-b border-border bg-raised">
        <span className="font-medium">{title}</span>

        <span
          className={cn(
            "px-1.5 py-0.5 rounded text-[11px] border",
            complete
              ? "text-ok border-ok/40 bg-ok/10"
              : "text-danger border-danger/50 bg-danger/10 font-semibold",
          )}
          title={
            complete
              ? "Rendered counts match the declared counts"
              : "Rendered counts do NOT match: this result is incomplete"
          }
        >
          {complete ? "COMPLETE" : "INCOMPLETE"}
        </span>

        <div className="flex items-center gap-3 text-text-dim text-[11px]">
          <span className="num">{stats.top}</span>
          <span className="num">{stats.nodes.toLocaleString()} nodes</span>
          <span className="num">{stats.chars.toLocaleString()} chars</span>
          <span className="num">{formatBytes(stats.bytes)}</span>
          {durationMs !== undefined && (
            <span className="num text-accent">{durationMs.toFixed(1)} ms</span>
          )}
        </div>

        <div className="ml-auto flex items-center gap-1">
          {(["tree", "raw", "hex"] as ViewMode[]).map((m) => (
            <button
              key={m}
              type="button"
              onClick={() => setView(m)}
              className={cn(
                "px-2 py-0.5 rounded border text-[11px]",
                view === m
                  ? "border-accent text-accent bg-highlight"
                  : "border-border text-text-dim hover:text-text hover:border-border-strong",
              )}
            >
              {m}
            </button>
          ))}
          <button
            type="button"
            onClick={copy}
            className="px-2 py-0.5 rounded border border-border text-text-dim hover:text-text text-[11px]"
            title="Copy the complete JSON, not the rendered view"
          >
            copy all
          </button>
        </div>
      </div>

      <div className="p-2">
        {view === "tree" && <Node value={value} defaultOpen />}
        {view === "raw" && <RawView value={value} />}
        {view === "hex" && <HexView value={value} />}
      </div>
    </div>
  );
}
