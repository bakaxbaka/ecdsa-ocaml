"use client";

import { useMemo } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import type { RunRecord } from "@/components/useRunLog";

/**
 * Charts over results that actually ran.
 *
 * Every series here is read out of a completed `statistics` (or `pipeline`)
 * response in the run log. There is no seeded, sampled or placeholder data: if
 * no such response exists yet, this renders an empty state naming the endpoint
 * that produces one. A chart with invented numbers would be worse than no chart,
 * because it would look like evidence.
 */

/** One labelled count, as the statistics encoder emits them. */
interface Slice {
  label: string;
  value: number;
}

const COLORS = ["#f7931a", "#00d4ff", "#00c853", "#ffb300", "#ff3d57", "#8b95a8"];

function toSlices(record: Record<string, unknown> | undefined, suffix: string): Slice[] {
  if (!record) return [];
  const out: Slice[] = [];
  for (const [k, v] of Object.entries(record)) {
    if (typeof v !== "number") continue;
    // The encoder names these `<thing>_count`; drop the suffix for the axis.
    const label = k.endsWith(suffix) ? k.slice(0, -suffix.length) : k;
    if (v === 0) continue;
    out.push({ label, value: v });
  }
  return out;
}

function Panel({ title, slices, note }: { title: string; slices: Slice[]; note?: string }) {
  return (
    <section className="border border-border rounded bg-panel p-3">
      <div className="flex items-baseline gap-2 mb-2">
        <h3 className="font-medium text-[13px]">{title}</h3>
        <span className="text-text-faint text-[11px] num">
          {slices.reduce((a, s) => a + s.value, 0).toLocaleString()} total
        </span>
      </div>
      {note && <div className="text-text-faint text-[11px] mb-2">{note}</div>}
      <div className="h-56">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={slices} margin={{ top: 4, right: 8, bottom: 4, left: 0 }}>
            <CartesianGrid stroke="#212838" vertical={false} />
            <XAxis
              dataKey="label"
              tick={{ fill: "#8b95a8", fontSize: 11 }}
              stroke="#2a3245"
              interval={0}
              angle={-25}
              textAnchor="end"
              height={64}
            />
            <YAxis tick={{ fill: "#8b95a8", fontSize: 11 }} stroke="#2a3245" allowDecimals={false} />
            <Tooltip
              contentStyle={{
                background: "#12161f",
                border: "1px solid #2a3245",
                borderRadius: 8,
                fontSize: 12,
              }}
              labelStyle={{ color: "#e8ecf4" }}
              itemStyle={{ color: "#a5b4c8" }}
            />
            <Bar dataKey="value" radius={[3, 3, 0, 0]}>
              {slices.map((s, i) => (
                <Cell key={s.label} fill={COLORS[i % COLORS.length]} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
}

/** Find the most recent run that carries aggregate statistics. */
function latestStats(runs: RunRecord[]) {
  for (let i = runs.length - 1; i >= 0; i -= 1) {
    const r = runs[i];
    const res = r.response as { stats?: Record<string, unknown> } | null;
    if (res && res.stats) return { record: r, stats: res.stats };
  }
  return null;
}

export function Charts({ runs }: { runs: RunRecord[] }) {
  const found = useMemo(() => latestStats(runs), [runs]);

  const panels = useMemo(() => {
    if (!found) return null;
    const s = found.stats;

    const sigForms = toSlices(s.sig_forms as Record<string, unknown>, "_count");
    const sighash = toSlices(s.sighash_types as Record<string, unknown>, "_count");
    const scripts = toSlices(s.script_types as Record<string, unknown>, "_count");
    const pubkeys = toSlices(s.pubkeys as Record<string, unknown>, "_count");

    const verify = s.ecdsa_verification as
      | { verified_count?: number; failed_count?: number; verification_rate?: number }
      | undefined;

    const verification: Slice[] = verify
      ? [
          { label: "verified", value: verify.verified_count ?? 0 },
          { label: "failed", value: verify.failed_count ?? 0 },
        ].filter((x) => x.value > 0)
      : [];

    return { sigForms, sighash, scripts, pubkeys, verification, verify };
  }, [found]);

  if (!found || !panels) {
    return (
      <section className="border border-border rounded bg-panel p-3">
        <h3 className="font-medium text-[13px] mb-1">No statistics to chart yet</h3>
        <p className="text-text-dim text-[12px] leading-relaxed">
          These charts read the aggregate distributions out of a completed{" "}
          <code className="data">statistics</code> result. Run{" "}
          <code className="data">Statistics</code> (or{" "}
          <code className="data">Full pipeline</code>) on a transaction and the signature-form,
          sighash-type, script-type and verification breakdowns appear here. Nothing is plotted until
          real numbers exist for it.
        </p>
      </section>
    );
  }

  const empty = (title: string) => (
    <section key={title} className="border border-border rounded bg-panel p-3">
      <h3 className="font-medium text-[13px] mb-1">{title}</h3>
      <p className="text-text-faint text-[11px]">
        The result carried no non-zero counts for this breakdown.
      </p>
    </section>
  );

  return (
    <div className="flex flex-col gap-4">
      <div className="text-text-dim text-[11px]">
        Source: run #{found.record.id} · {found.record.label}
        {found.record.durationMs !== null && (
          <span className="num text-accent"> · {found.record.durationMs.toFixed(1)} ms</span>
        )}
        <span className="text-text-faint">
          {" "}
          · each panel sums only what the server reported; zero-count buckets are omitted rather
          than drawn as zero.
        </span>
      </div>

      {panels.sigForms.length > 0 ? (
        <Panel
          title="Signature form (low-S vs high-S)"
          slices={panels.sigForms}
          note="Low-S is the BIP62 canonical form. A high-S share is a normality signal, not a vulnerability."
        />
      ) : (
        empty("Signature form (low-S vs high-S)")
      )}

      {panels.sighash.length > 0 ? (
        <Panel
          title="Sighash type distribution"
          slices={panels.sighash}
          note="SIGHASH_ALL / NONE / SINGLE, and whether ANYONECANPAY was set."
        />
      ) : (
        empty("Sighash type distribution")
      )}

      {panels.scripts.length > 0 ? (
        <Panel title="Script types spent" slices={panels.scripts} />
      ) : (
        empty("Script types spent")
      )}

      {panels.verification.length > 0 ? (
        <>
          <Panel
            title="ECDSA verification"
            slices={panels.verification}
            note="Verified and failed are separate counts from the engine. They are not complemented: a signature that could not be checked at all is in neither bucket."
          />
          {panels.verify?.verification_rate !== undefined && (
            <div className="text-text-dim text-[11px]">
              Reported verification rate:{" "}
              <span className="num text-text">
                {(panels.verify.verification_rate * 100).toFixed(2)}%
              </span>{" "}
              <span className="text-text-faint">
                {" — the engine's own figure, shown unrounded and unadjusted."}
              </span>
            </div>
          )}
        </>
      ) : (
        empty("ECDSA verification")
      )}

      {panels.pubkeys.length > 0 ? (
        <Panel
          title="Public keys"
          slices={panels.pubkeys}
          note="Compressed vs uncompressed encodings, and how many keys could not be recovered as curve points."
        />
      ) : (
        empty("Public keys")
      )}
    </div>
  );
}
