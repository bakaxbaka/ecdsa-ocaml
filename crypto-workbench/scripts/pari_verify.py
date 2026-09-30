#!/usr/bin/env python3
"""pari_verify.py — cross-language ECDSA verification of reconstructed z values using PARI/GP.

Writes a sample of signatures (all 874 target sigs + deterministic sample of others)
to target/cache/pari_sigs.csv, runs pari/verify_sigs.gp with gp -q, and compares
PARI's independent elliptic-curve verification results with the Python/OpenSSL ones.
"""
import csv, os, random, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
WB = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(WB, "python"))
T = os.path.join(WB, "target")

def main():
    rows = list(csv.DictReader(open(os.path.join(T, "signatures.tsv")), delimiter="\t"))
    zmap = {}
    for r in csv.DictReader(open(os.path.join(T, "z_values.tsv")), delimiter="\t"):
        zmap[(r["txid"], r["vin"])] = r["z_dec"]
    target = [r for r in rows if r["is_target_key"] == "1"]
    others = [r for r in rows if r["is_target_key"] != "1" and r["pubkey"]]
    rng = random.Random(777)
    sample = target + rng.sample(others, min(150, len(others)))
    print(f"verifying with PARI/GP: {len(target)} target sigs + {len(sample)-len(target)} sampled others")

    csvp = os.path.join(T, "cache", "pari_sigs.csv")
    os.makedirs(os.path.dirname(csvp), exist_ok=True)
    with open(csvp, "w") as f:
        for r in sample:
            z = zmap[(r["txid"], r["vin"])]
            f.write(f'[{r["r_dec"]}, {r["s_dec"]}, {z}, "{r["pubkey"]}"]\n')

    t0 = time.time()
    gp = os.path.join(WB, "pari", "verify_sigs.gp")
    env = dict(os.environ, PARI_SIGS=csvp)
    out = subprocess.run(["gp", "-q", gp], capture_output=True, text=True, timeout=1800, env=env)
    dt = time.time() - t0
    if out.returncode != 0:
        print("GP FAILED:", out.stderr[:2000]); sys.exit(1)
    lines = [l for l in out.stdout.splitlines() if l.strip()]
    results = {}
    for l in lines:
        parts = l.split()
        if len(parts) == 2 and parts[1] in ("OK", "FAIL"):
            results[int(parts[0])] = parts[1]
    okc = sum(1 for v in results.values() if v == "OK")
    print(f"PARI results: {okc}/{len(results)} OK in {dt:.1f}s")
    mism = []
    for i, r in enumerate(sample):
        pari_ok = results.get(i) == "OK"
        py_ok = r["verify_openssl"] == "True"
        if pari_ok != py_ok:
            mism.append((i, r["txid"], r["vin"]))
    print(f"python-vs-pari disagreements: {len(mism)}")
    with open(os.path.join(T, "cache", "pari_verify_result.json"), "w") as f:
        import json
        json.dump({"n_sample": len(sample), "n_target": len(target), "pari_ok": okc,
                   "disagreements": mism, "runtime_s": round(dt, 1)}, f, indent=1)
    sys.exit(0 if (okc == len(sample) and not mism) else 2)

if __name__ == "__main__":
    main()
