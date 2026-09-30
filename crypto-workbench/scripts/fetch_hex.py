#!/usr/bin/env python3
"""Fetch raw transaction hex for every txid, with caching/backoff/resume.

Primary:   mempool.space    /api/tx/<txid>/hex   -> target/rawtx/<txid>.hex
Cross:     blockstream.info /api/tx/<txid>/hex   -> target/rawtx_blockstream/<txid>.hex
           (fetched for: all txs spending target outputs + a deterministic sample)

Usage: fetch_hex.py [mempool|blockstream|both]
Conservative concurrency (2 CPU / 1 GB RAM box, I/O bound): 4 workers primary, 2 cross.
"""
import json, os, sys, time, random, hashlib, threading, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

WB = os.environ.get("ARENA_WORKSPACE") or os.path.expanduser("~")
BASE = os.path.join(WB, "crypto-workbench", "target")
ADDR = "17GGGHWtyi7e1rxnEpcKpE7fHq1UZBguAb"
API = {"mempool": "https://mempool.space/api", "blockstream": "https://blockstream.info/api"}
UA = "crypto-workbench-research/1.0 (public-data forensics; local container)"
_local = threading.local()

def get_text(url, timeout=40, max_tries=8):
    for attempt in range(max_tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read().decode().strip()
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504):
                wait = min(45, (2 ** attempt) + random.uniform(0, 1.5))
                time.sleep(wait); continue
            raise
        except Exception:
            time.sleep(min(20, 2 ** attempt * 0.5 + random.uniform(0, 0.5)))
    raise RuntimeError(f"gave up: {url}")

def dsha(b): 
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def load_txs():
    txs = {}
    with open(os.path.join(BASE, "transactions.jsonl")) as f:
        for line in f:
            tx = json.loads(line)
            txs[tx["txid"]] = tx
    return txs

def spending_and_sample(txs):
    """txids whose inputs spend target outputs (need z), plus deterministic sample of the rest."""
    spending, other = set(), set()
    for t, tx in txs.items():
        is_sp = any(v.get("prevout", {}).get("scriptpubkey_address") == ADDR
                    for v in tx.get("vin", []))
        (spending if is_sp else other).add(t)
    rng = random.Random(12345)  # deterministic seed
    sample = set(rng.sample(sorted(other), min(250, len(other))))
    return spending, sample

def fetch_one(txid, src, outdir):
    out = os.path.join(outdir, f"{txid}.hex")
    if os.path.exists(out) and os.path.getsize(out) > 10:
        return txid, "cached"
    hx = get_text(f"{API[src]}/tx/{txid}/hex")
    hx = "".join(hx.split()).lower()
    try:
        bytes.fromhex(hx)
    except ValueError:
        return txid, f"BADHEX:{hx[:40]}"
    tmp = out + ".tmp"
    with open(tmp, "w") as f: f.write(hx + "\n")
    os.replace(tmp, out)
    time.sleep(random.uniform(0.03, 0.09))
    return txid, "fetched"

def run_source(src, txids, outdir, workers, label):
    os.makedirs(outdir, exist_ok=True)
    todo = [t for t in txids if not (os.path.exists(os.path.join(outdir, t + ".hex"))
            and os.path.getsize(os.path.join(outdir, t + ".hex")) > 10)]
    print(f"[{label}] {len(txids)} txids, {len(txids)-len(todo)} cached, {len(todo)} to fetch", flush=True)
    done = fails = 0
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(fetch_one, t, src, outdir): t for t in todo}
        for fu in as_completed(futs):
            t = futs[fu]
            try:
                _, st = fu.result()
                if st.startswith("BADHEX") or st == "error": fails += 1; print(f"[{label}] FAIL {t}: {st}", flush=True)
                else: done += 1
            except Exception as e:
                fails += 1; print(f"[{label}] ERR {t}: {type(e).__name__}: {e}", flush=True)
            if (done + fails) % 500 == 0:
                print(f"[{label}] {done+fails}/{len(todo)} ({time.time()-t0:.0f}s, fails={fails})", flush=True)
    print(f"[{label}] finished: {done} ok, {fails} fail in {time.time()-t0:.0f}s", flush=True)
    return fails

def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "both"
    txs = load_txs()
    all_ids = sorted(txs)
    spending, sample = spending_and_sample(txs)
    print(f"txids: {len(all_ids)} total; spending-target: {len(spending)}; crosscheck sample: {len(sample)}", flush=True)
    if which in ("mempool", "both"):
        run_source("mempool", all_ids, os.path.join(BASE, "rawtx"), 4, "mempool/all")
    if which in ("blockstream", "both"):
        cross = sorted(spending | sample)
        run_source("blockstream", cross, os.path.join(BASE, "rawtx_blockstream"), 2, "blockstream/crosscheck")
    # reconcile: byte-compare everything present in both dirs
    d1, d2 = os.path.join(BASE, "rawtx"), os.path.join(BASE, "rawtx_blockstream")
    common = sorted(set(os.listdir(d1)) & set(os.listdir(d2)))
    mism = [f for f in common if open(os.path.join(d1, f)).read().strip() != open(os.path.join(d2, f)).read().strip()]
    print(f"reconcile: {len(common)} hex files in both sources; mismatches: {len(mism)}")
    if mism: print("MISMATCHES:", mism[:10])
    # integrity: txid == dsha256(non-witness serialization) checked later by parser; here quick sanity on a few
    print("DONE")

if __name__ == "__main__":
    main()
