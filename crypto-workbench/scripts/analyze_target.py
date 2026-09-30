#!/usr/bin/env python3
"""analyze_target.py — statistical/forensic analysis of extracted signatures.

Analyses (per task spec):
 1 duplicate r | 2 duplicate (r,s) | 3 r/s range | 4 low/high-S | 5 per-bit frequency
 6 entropy | 7 Hamming weight | 8 adjacent bits | 9 r/s/z correlations
 10 tx/input reuse | 11 input-value patterns | 12 output-value patterns
 13 script patterns | 14 encoding anomalies | 15 sighash distribution
 16 pubkey consistency | 17 chronological statistics

Outputs results/target_analysis.json + figures. Deterministic (fixed seeds).
NOTE: statistical deviation != cryptographic vulnerability; every claim is
reported with its test statistic and sample-size caveat.
"""
import csv, json, math, os, sys, collections, itertools, random, time

HERE = os.path.dirname(os.path.abspath(__file__))
WB = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(WB, "python"))
import btclib as B

T = os.path.join(WB, "target")
RES = os.path.join(WB, "results")
os.makedirs(RES, exist_ok=True)
N_CURVE = B.N
P_CURVE = B.P

def popcount(x): return bin(x).count("1")

def bitfreq_stats(values, nbits=256):
    """per-bit frequency of 1s across values; returns dict"""
    n = len(values)
    counts = [0] * nbits
    for v in values:
        for i in range(nbits):
            counts[i] += (v >> i) & 1
    # normal approximation z-score per bit
    exp, sd = n / 2, math.sqrt(n) / 2
    zscores = [(c - exp) / sd for c in counts]
    zmax = max(zscores, key=abs)
    n_sig3 = sum(1 for z in zscores if abs(z) > 3.0)
    # Bonferroni threshold for 256 tests at family-wise 0.05: |z| > 3.55
    n_sigb = sum(1 for z in zscores if abs(z) > 3.55)
    mean_h = 0.0
    for c in counts:
        p1 = c / n
        if 0 < p1 < 1:
            mean_h += -(p1 * math.log2(p1) + (1 - p1) * math.log2(1 - p1))
        # p1==0 or 1 contributes 0
    mean_h /= nbits
    return {"n_samples": n, "min_ones": min(counts), "max_ones": max(counts),
            "expected_ones": exp, "z_max_abs": round(max(zscores, key=abs), 3),
            "bits_|z|>3": n_sig3, "bits_|z|>3.55_bonferroni": n_sigb,
            "mean_per_bit_entropy_bits": round(mean_h, 5),
            "zscore_per_bit": [round(z, 3) for z in zscores]}

def shannon_bytes(data: bytes):
    c = collections.Counter(data)
    n = len(data)
    return -sum((k / n) * math.log2(k / n) for k in c.values())

def uniformity_mods(values, mods=(2, 3, 5, 7, 11, 13, 251, 257)):
    out = {}
    n = len(values)
    for m in mods:
        c = collections.Counter(v % m for v in values)
        chi2 = sum((c.get(r, 0) - n / m) ** 2 / (n / m) for r in range(m))
        out[f"mod{m}_chi2"] = round(chi2, 2)
        out[f"mod{m}_df"] = m - 1
    return out

def main():
    t0 = time.time()
    sigs = list(csv.DictReader(open(os.path.join(T, "signatures.tsv")), delimiter="\t"))
    zrows = list(csv.DictReader(open(os.path.join(T, "z_values.tsv")), delimiter="\t"))
    zmap = {(r["txid"], r["vin"]): int(r["z_dec"]) for r in zrows}
    inputs = list(csv.DictReader(open(os.path.join(T, "inputs.tsv")), delimiter="\t"))
    outputs = list(csv.DictReader(open(os.path.join(T, "outputs.tsv")), delimiter="\t"))
    ver = json.load(open(os.path.join(T, "verification.json")))

    tgt = [s for s in sigs if s["is_target_key"] == "1"]
    print(f"sigs total={len(sigs)} target={len(tgt)}")

    A = {}   # analysis results
    A["counts"] = {"txs": ver["tx_count"], "inputs": ver["stats"]["inputs"],
                   "outputs": len(outputs), "signatures_all": len(sigs),
                   "signatures_target": len(tgt),
                   "schnorr_inputs": ver["stats"]["schnorr"]}

    # ---- 1/2 duplicate r, duplicate (r,s) ----
    def dup_report(rows, label):
        rc = collections.Counter(r["r_hex"] for r in rows)
        rsc = collections.Counter((r["r_hex"], r["s_hex"]) for r in rows)
        dupr = {k: v for k, v in rc.items() if v > 1}
        duprs = {k: v for k, v in rsc.items() if v > 1}
        return {f"{label}_n": len(rows), f"{label}_unique_r": len(rc),
                f"{label}_dup_r_groups": len(dupr), f"{label}_dup_r_examples": list(dupr)[:5],
                f"{label}_unique_rs": len(rsc), f"{label}_dup_rs_groups": len(duprs)}
    A["duplicates"] = {}
    A["duplicates"].update(dup_report(tgt, "target"))
    A["duplicates"].update(dup_report(sigs, "all"))
    # per-pubkey duplicate r across ALL sigs (nonce reuse is per-key)
    bypk = collections.defaultdict(list)
    for s in sigs:
        if s["pubkey"]: bypk[s["pubkey"]].append(s)
    per_key_dup = {}
    for pk, rows in bypk.items():
        rc = collections.Counter(r["r_hex"] for r in rows)
        d = sum(v - 1 for v in rc.values() if v > 1)
        if d: per_key_dup[pk[:16] + "..."] = {"n_sigs": len(rows), "dup_r": d}
    A["duplicates"]["per_pubkey_dup_r_keys"] = per_key_dup
    A["duplicates"]["per_pubkey_groups"] = len(bypk)

    # ---- 3 range validation ----
    rng_bad = []
    for s in tgt:
        r_i, s_i = int(s["r_dec"]), int(s["s_dec"])
        if not (1 <= r_i < N_CURVE and 1 <= s_i < N_CURVE): rng_bad.append(s["txid"])
        if r_i >= P_CURVE: rng_bad.append("r>=p:" + s["txid"])
    A["range_validation"] = {"target_out_of_range": len(rng_bad), "examples": rng_bad[:5],
                             "r_min": min(int(s['r_dec']) for s in tgt),
                             "r_max": max(int(s['r_dec']) for s in tgt),
                             "s_min": min(int(s['s_dec']) for s in tgt),
                             "s_max": max(int(s['s_dec']) for s in tgt),
                             "n": N_CURVE}

    # ---- 4 low-S ----
    lows = sum(1 for s in tgt if s["low_s"] == "1")
    A["low_s"] = {"target_low_s": lows, "target_high_s": len(tgt) - lows,
                  "all_low_s": sum(1 for s in sigs if s["low_s"] == "1"), "all_n": len(sigs)}

    # ---- 5/6/7/8 bit-level statistics ----
    rs = [int(s["r_dec"]) for s in tgt]
    ss = [int(s["s_dec"]) for s in tgt]
    zs = [zmap[(s["txid"], s["vin"])] for s in tgt]
    A["bitfreq_r"] = bitfreq_stats(rs)
    A["bitfreq_s"] = bitfreq_stats(ss)
    A["bitfreq_s"]["note_bit255"] = ("s<=n/2 (BIP147/BIP62 low-S policy) forces bit255(s)=0 for all samples; "
                                     "the |z|>3.55 flag at bit 255 (and near-Msb bits) is an artifact of this "
                                     "deterministic normalization, NOT RNG bias.")
    A["bitfreq_z"] = bitfreq_stats(zs)
    zb_r = b"".join(v.to_bytes(32, "big") for v in rs)
    zb_s = b"".join(v.to_bytes(32, "big") for v in ss)
    zb_z = b"".join(v.to_bytes(32, "big") for v in zs)
    A["byte_entropy"] = {"r_bytes_shannon": round(shannon_bytes(zb_r), 4),
                         "s_bytes_shannon": round(shannon_bytes(zb_s), 4),
                         "z_bytes_shannon": round(shannon_bytes(zb_z), 4),
                         "max_possible": 8.0}
    A["uniformity"] = {"r": uniformity_mods(rs), "s": uniformity_mods(ss), "z": uniformity_mods(zs)}
    hw_r = [popcount(v) for v in rs]; hw_s = [popcount(v) for v in ss]; hw_z = [popcount(v) for v in zs]
    A["hamming"] = {"r_mean": round(sum(hw_r)/len(hw_r), 3), "r_sd": round((sum((x-sum(hw_r)/len(hw_r))**2 for x in hw_r)/len(hw_r))**0.5, 3),
                    "s_mean": round(sum(hw_s)/len(hw_s), 3), "z_mean": round(sum(hw_z)/len(hw_z), 3),
                    "expected_mean": 128.0, "expected_sd": 8.0,
                    "r_min": min(hw_r), "r_max": max(hw_r),
                    "hist_r": dict(collections.Counter(hw_r))}
    # adjacent-bit agreement
    def adj_stats(values):
        agree = tot = 0
        for v in values:
            for i in range(255):
                agree += ((v >> i) & 1) == ((v >> (i + 1)) & 1)
                tot += 1
        return {"P(adjacent_equal)": round(agree / tot, 5), "expected": 0.5,
                "z": round((agree / tot - 0.5) / math.sqrt(0.25 / tot), 2)}
    A["adjacent_bits"] = {"r": adj_stats(rs), "s": adj_stats(ss), "z": adj_stats(zs)}

    # ---- 9 correlations ----
    def pearson(x, y):
        n = len(x); mx, my = sum(x)/n, sum(y)/n
        cov = sum((a-mx)*(b-my) for a, b in zip(x, y))
        vx = sum((a-mx)**2 for a in x); vy = sum((b-my)**2 for b in y)
        return cov / math.sqrt(vx * vy) if vx and vy else float("nan")
    def norm(vals):  # scale to [0,1)
        m = max(vals)
        return [v / (m + 1) for v in vals]
    A["correlations"] = {
        "pearson_r_s": round(pearson(norm(rs), norm(ss)), 4),
        "pearson_r_z": round(pearson(norm(rs), norm(zs)), 4),
        "pearson_s_z": round(pearson(norm(ss), norm(zs)), 4),
        "pearson_r_lag1_chrono": None, "pearson_s_lag1_chrono": None,
        "bitwise_r_s_max_abs_corr": None,
    }
    # ---- 10 tx/input reuse ----
    tgt_inputs = [i for i in inputs if i["spends_target"] == "1"]
    per_tx = collections.Counter(i["txid"] for i in tgt_inputs)
    prev_parents = collections.Counter(i["prev_txid"] for i in tgt_inputs)
    A["input_reuse"] = {
        "spending_txs": len(per_tx),
        "inputs_per_tx": dict(sorted(per_tx.items(), key=lambda kv: -kv[1])),
        "same_parent_tx_multi_spend": {k[:16] + "...": v for k, v in prev_parents.items() if v > 1},
        "n_distinct_parents": len(prev_parents),
        "prev_vout_distribution_top10": dict(collections.Counter(i["prev_vout"] for i in tgt_inputs).most_common(10)),
        "sequence_values": dict(collections.Counter(i["sequence"] for i in tgt_inputs)),
    }
    # ---- 11 input value patterns ----
    vals = [int(i["prevout_value"]) for i in tgt_inputs if i["prevout_value"]]
    vc = collections.Counter(vals)
    A["input_values"] = {"n": len(vals), "distinct": len(vc), "sum_btc": sum(vals)/1e8,
                         "min": min(vals), "max": max(vals), "mean": round(sum(vals)/len(vals), 1),
                         "top_repeated": [(v, c) for v, c in vc.most_common(8) if c > 1],
                         "n_repeated": sum(1 for v, c in vc.items() if c > 1)}
    # ---- 12 output value patterns (spending txs) ----
    sp_txids = set(per_tx)
    sp_outs = [o for o in outputs if o["txid"] in sp_txids]
    ovc = collections.Counter(int(o["value"]) for o in sp_outs)
    back_to_target = [o for o in sp_outs if o["is_target"] == "1"]
    A["output_values"] = {"spending_tx_outputs": len(sp_outs), "distinct_values": len(ovc),
                          "top_repeated": [(v, c) for v, c in ovc.most_common(8) if c > 1],
                          "outputs_back_to_target": len(back_to_target),
                          "change_sum_btc": sum(int(o["value"]) for o in back_to_target)/1e8}
    # ---- 13 script patterns ----
    A["script_patterns"] = {
        "all_outputs_by_type": dict(collections.Counter(o["spk_type"] for o in outputs)),
        "top_output_addresses": [a for a, _ in collections.Counter(o["address"] for o in outputs if o["address"]).most_common(5)],
        "target_inputs_prevout_type": dict(collections.Counter(i["prevout_type"] for i in tgt_inputs)),
    }
    # ---- 14/15 encoding anomalies + sighash ----
    A["encoding"] = {"der_nonstrict_all": ver["stats"]["der_nonstrict"],
                     "high_s_all": ver["stats"]["high_s"],
                     "anomalies_file_rows": sum(1 for _ in open(os.path.join(T, "anomalies.tsv"))) - 1,
                     "sighash_distribution_all": {k: v for k, v in ver["stats"]["shtypes"].items()},
                     "sig_len_distribution_target": dict(collections.Counter(len(bytes.fromhex(s["r_hex"])+bytes.fromhex(s["s_hex"])) for s in tgt))}
    # ---- 16 pubkey consistency ----
    pks = set(s["pubkey"] for s in tgt)
    h160s = set(s["pubkey_h160"] for s in tgt)
    pk = list(pks)[0] if len(pks) == 1 else None
    A["pubkey"] = {"unique_pubkeys": len(pks), "pubkey": pk,
                   "all_h160_equal_target": h160s == {B.hash160(bytes.fromhex(pk)).hex()} if pk else None,
                   "compressed": (len(bytes.fromhex(pk)) == 33) if pk else None,
                   "derived_address": B.b58check_encode(b"\x00" + B.hash160(bytes.fromhex(pk))) if pk else None,
                   "matches_target_address": (B.b58check_encode(b"\x00" + B.hash160(bytes.fromhex(pk))) == "17GGGHWtyi7e1rxnEpcKpE7fHq1UZBguAb") if pk else None}
    # ---- 17 chronological ----
    chrono = sorted(tgt, key=lambda s: (int(s["block_height"]), int(s["vin"])))
    crs = [int(s["r_dec"]) for s in chrono]; css = [int(s["s_dec"]) for s in chrono]
    A["correlations"]["pearson_r_lag1_chrono"] = round(pearson(norm(crs[:-1]), norm(crs[1:])), 4)
    A["correlations"]["pearson_s_lag1_chrono"] = round(pearson(norm(css[:-1]), norm(css[1:])), 4)
    # bitwise r-s correlation max
    maxc = 0.0
    for i in range(256):
        xb = [(v >> i) & 1 for v in rs]; yb = [(v >> i) & 1 for v in ss]
        if 0 < sum(xb) < len(xb) and 0 < sum(yb) < len(yb):
            maxc = max(maxc, abs(pearson(xb, yb)))
    A["correlations"]["bitwise_r_s_max_abs_corr"] = round(maxc, 4)
    heights = [int(s["block_height"]) for s in chrono]
    times = [int(s["block_time"]) for s in chrono]
    by_tx_meta = {}
    for s in chrono:
        by_tx_meta.setdefault(s["txid"], (int(s["block_height"]), int(s["block_time"])))
    meta_sorted = sorted(by_tx_meta.values())
    A["chronology"] = {
        "first_block": meta_sorted[0][0], "last_block": meta_sorted[-1][0],
        "first_time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(meta_sorted[0][1])),
        "last_time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(meta_sorted[-1][1])),
        "spending_tx_blocks": [m[0] for m in meta_sorted],
        "days_between_spending_txs": [round((meta_sorted[i+1][1]-meta_sorted[i][1])/86400, 1) for i in range(len(meta_sorted)-1)],
        "sigs_per_tx_chrono": [(h, sum(1 for s in chrono if int(s["block_height"]) == h)) for h in sorted(set(heights))],
        "hw_r_by_year": {},
    }
    by_year = collections.defaultdict(list)
    for s, hwc in zip(chrono, [popcount(int(x["r_dec"])) for x in chrono]):
        by_year[time.gmtime(int(s["block_time"])).tm_year].append(hwc)
    A["chronology"]["hw_r_by_year"] = {y: {"n": len(v), "mean": round(sum(v)/len(v), 2)} for y, v in sorted(by_year.items())}

    # ---- KS tests (scipy) ----
    try:
        from scipy import stats as st
        ks_r = st.kstest([v / N_CURVE for v in rs], "uniform")
        # s is low-S-normalized (s <= n/2): test the rescaled variable 2s/n vs U(0,1)
        ks_s = st.kstest([2 * v / N_CURVE for v in ss], "uniform")
        ks_s_full = st.kstest([v / N_CURVE for v in ss], "uniform")
        A.setdefault("ks_tests", {})
        ks_z = st.kstest([v / (2**256) for v in zs], "uniform")
        A["ks_tests"] = {"r_vs_uniform": {"stat": round(ks_r.statistic, 5), "p": round(ks_r.pvalue, 4)},
                         "s_rescaled_2s_over_n_vs_uniform": {"stat": round(ks_s.statistic, 5), "p": round(ks_s.pvalue, 4)},
                         "s_vs_uniform_full_range_expected_fail_due_to_low_s": {"stat": round(ks_s_full.statistic, 5), "p": round(ks_s_full.pvalue, 4)},
                         "z_vs_uniform": {"stat": round(ks_z.statistic, 5), "p": round(ks_z.pvalue, 4)},
                         "hamming_r_vs_binom256": None}
        # hamming distribution KS vs binomial
        import numpy as _np
        ks_h = st.ks_1samp(hw_r, lambda x: st.binom.cdf(_np.floor(_np.asarray(x, dtype=float)), 256, 0.5))
        A["ks_tests"]["hamming_r_vs_binom256"] = {"stat": round(ks_h.statistic, 5), "p": round(ks_h.pvalue, 4)}
    except Exception as e:
        A["ks_tests"] = {"error": str(e)}

    A["runtime_s"] = round(time.time() - t0, 1)
    with open(os.path.join(RES, "target_analysis.json"), "w") as f:
        json.dump(A, f, indent=1, default=str)
    print(json.dumps({k: v for k, v in A.items() if k in
                      ("counts", "duplicates", "low_s", "byte_entropy", "adjacent_bits",
                       "correlations", "pubkey", "ks_tests", "hamming", "encoding")},
                     indent=1, default=str)[:3000])
    print("target_analysis.json written")

if __name__ == "__main__":
    main()
