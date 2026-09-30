"use client";

import { useEffect, useMemo, useState } from "react";
import { api, type Catalogue, type ModuleInfo } from "@/lib/api";
import { cn } from "@/lib/utils";

/**
 * The function catalogue.
 *
 * Populated from the server, which derives it by parsing the project's `.mli`
 * files. Nothing here is hand-written, so the list cannot drift from the code.
 *
 * Exposes everything: 25 modules and every declaration in them, grouped by the
 * dune library that provides them. No entry is filtered, abbreviated, or
 * collapsed away by default.
 */
export function CatalogueRail({
  onUseSignature,
}: {
  onUseSignature: (decl: { name: string; signature: string; module: string }) => void;
}) {
  const [cat, setCat] = useState<Catalogue | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});

  useEffect(() => {
    let cancelled = false;
    api
      .functions()
      .then((env) => {
        if (!cancelled) setCat(env.result);
      })
      .catch((e) => {
        if (!cancelled) setError(String(e));
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const filtered: ModuleInfo[] = useMemo(() => {
    if (!cat) return [];
    const q = query.trim().toLowerCase();
    if (!q) return cat.modules;
    return cat.modules
      .map((m) => ({
        ...m,
        decls: m.decls.filter(
          (d) =>
            d.name.toLowerCase().includes(q) ||
            d.signature.toLowerCase().includes(q) ||
            (d.doc ?? "").toLowerCase().includes(q),
        ),
      }))
      .filter(
        (m) =>
          m.decls.length > 0 ||
          m.module.toLowerCase().includes(q) ||
          (m.doc ?? "").toLowerCase().includes(q),
      );
  }, [cat, query]);

  const shownDecls = filtered.reduce((a, m) => a + m.decls.length, 0);

  const byLibrary = useMemo(() => {
    const groups = new Map<string, ModuleInfo[]>();
    for (const m of filtered) {
      const arr = groups.get(m.library) ?? [];
      arr.push(m);
      groups.set(m.library, arr);
    }
    return [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [filtered]);

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="px-3 py-2 border-b border-border">
        <div className="flex items-baseline justify-between">
          <span className="font-medium">Catalogue</span>
          <span className="text-text-dim text-[11px] num">
            {/* Loading placeholder, not elided data. */}
            {/* no-truncation-check-allow */}
            {cat ? `${shownDecls} / ${cat.declaration_count}` : "…"}
          </span>
        </div>
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Filter functions, types, docs…" /* no-truncation-check-allow */
          className="mt-2 w-full bg-bg border border-border rounded px-2 py-1 text-[12px] placeholder:text-text-faint"
          aria-label="Filter the function catalogue"
        />
        {cat && (
          <div className="text-text-faint text-[11px] mt-1">
            {cat.module_count} modules · {cat.declaration_count} declarations · derived from .mli
          </div>
        )}
      </div>

      <div className="overflow-y-auto min-h-0 flex-1">
        {error && (
          <div className="p-3 text-danger">
            Could not load the catalogue.
            <div className="data mt-1 text-text-dim">{error}</div>
          </div>
        )}
        {/* Loading placeholder, not elided data. */}
        {/* no-truncation-check-allow */}
        {!cat && !error && <div className="p-3 text-text-dim">Loading catalogue…</div>}

        {byLibrary.map(([library, modules]) => (
          <div key={library} className="border-b border-border">
            <div className="px-3 py-1 bg-raised text-[11px] uppercase tracking-wide text-text-dim">
              {library}
            </div>
            {modules.map((m) => {
              const open = !collapsed[m.module];
              return (
                <div key={m.file + m.module}>
                  <button
                    type="button"
                    onClick={() => setCollapsed((c) => ({ ...c, [m.module]: !!open }))}
                    className="w-full flex items-baseline gap-2 px-3 py-1 hover:bg-raised text-left"
                    aria-expanded={open}
                  >
                    <span className="text-text-faint w-3 shrink-0">{open ? "▾" : "▸"}</span>
                    <span className="font-medium">{m.module}</span>
                    <span className="text-text-faint text-[11px] num ml-auto">
                      {m.decl_count}
                    </span>
                  </button>
                  {open && (
                    <div className="pb-1">
                      {m.doc && (
                        <div className="px-3 pb-1 text-text-dim text-[11px] leading-snug">
                          {m.doc}
                        </div>
                      )}
                      {m.decls.map((d, i) => (
                        <button
                          key={`${d.name}-${i}`}
                          type="button"
                          onClick={() =>
                            onUseSignature({ name: d.name, signature: d.signature, module: m.module })
                          }
                          title={d.signature}
                          className="w-full text-left px-3 py-0.5 pl-6 hover:bg-highlight group"
                        >
                          <div className="flex items-baseline gap-2">
                            <span
                              className={cn(
                                "text-[10px] uppercase shrink-0 w-12",
                                d.kind === "val"
                                  ? "text-accent"
                                  : d.kind === "type"
                                    ? "text-warn"
                                    : "text-text-faint",
                              )}
                            >
                              {d.kind}
                            </span>
                            <span className="inline-data text-text flex-1">{d.name}</span>
                            <span className="text-text-faint text-[10px] num shrink-0">
                              {d.file.split("/").pop()}:{d.line}
                            </span>
                          </div>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ))}

        {cat && shownDecls === 0 && (
          <div className="p-3 text-text-dim">No declaration matches “{query}”.</div>
        )}
      </div>
    </div>
  );
}
