#!/usr/bin/env python3
"""Fetch COMPLETE confirmed tx history for target address from esplora-style APIs.

Primary: mempool.space   Cross-check: blockstream.info
Writes (under <WB>/target):
  cache/<src>_pages/page_NNNN.json      (raw API pages, cached => resumable)
  cache/<src>_address.json              (address stats)
  txids.txt                             (deduplicated)
  transactions_<src>.jsonl              (full tx JSON per source)
  transactions.jsonl                    (merged; mempool primary, blockstream fills gaps)
Robust: retries w/ exponential backoff+jitter, resume from cache, HTTP 429 handling.
Stdlib only.
"""
import json, os, sys, time, random, urllib.request, urllib.error

WB = os.environ.get("ARENA_WORKSPACE") or os.path.expanduser("~")
BASE = os.path.join(WB, "crypto-workbench", "target")
ADDR = "17GGGHWtyi7e1rxnEpcKpE7fHq1UZBguAb"
SOURCES = {
    "mempool": "https://mempool.space/api",
    "blockstream": "https://blockstream.info/api",
}
UA = "crypto-workbench-research/1.0 (public-data forensics; local container)"

def get(url, timeout=45, max_tries=8):
    for attempt in range(max_tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504):
                wait = min(60, (2 ** attempt) + random.uniform(0, 1.5))
                sys.stderr.write(f"[{e.code}] {url} retry in {wait:.1f}s (try {attempt+1})\n"); sys.stderr.flush()
                time.sleep(wait); continue
            raise
        except Exception as e:
            wait = min(30, (2 ** attempt) * 0.5 + random.uniform(0, 1))
            sys.stderr.write(f"[ERR {type(e).__name__}: {e}] {url} retry in {wait:.1f}s (try {attempt+1})\n"); sys.stderr.flush()
            time.sleep(wait)
    raise RuntimeError(f"gave up on {url}")

def fetch_all_txs(src_name, api):
    pages_dir = os.path.join(BASE, "cache", f"{src_name}_pages")
    os.makedirs(pages_dir, exist_ok=True)
    all_txs, seen = [], set()
    last_txid, page, empty_streak = None, 0, 0
    while True:
        url = (f"{api}/address/{ADDR}/txs" if last_txid is None
               else f"{api}/address/{ADDR}/txs/chain/{last_txid}")
        pfile = os.path.join(pages_dir, f"page_{page:04d}.json")
        if os.path.exists(pfile) and os.path.getsize(pfile) > 2:
            data = json.load(open(pfile))
        else:
            raw = get(url)
            data = json.loads(raw)
            tmp = pfile + ".tmp"
            with open(tmp, "wb") as f: f.write(raw)
            os.replace(tmp, pfile)
            time.sleep(0.12 + random.uniform(0, 0.13))  # conservative rate limiting
        if not data:
            empty_streak += 1
            if empty_streak >= 1:
                break
        new = 0
        for tx in data:
            t = tx["txid"]
            if t not in seen:
                seen.add(t); all_txs.append(tx); new += 1
        if data:
            last_txid = data[-1]["txid"]
        page += 1
        if page % 10 == 0 or not data:
            sys.stderr.write(f"[{src_name}] page {page}: {len(data)} txs ({new} new), total {len(all_txs)}\n"); sys.stderr.flush()
        if new == 0 and data:
            break  # no progress => safety stop
    return all_txs

def main():
    os.makedirs(os.path.join(BASE, "cache"), exist_ok=True)
    for name, api in SOURCES.items():
        stats_file = os.path.join(BASE, "cache", f"{name}_address.json")
        if not os.path.exists(stats_file):
            with open(stats_file, "wb") as f:
                f.write(get(f"{api}/address/{ADDR}"))
    results = {}
    for name, api in SOURCES.items():
        t0 = time.time()
        txs = fetch_all_txs(name, api)
        out = os.path.join(BASE, f"transactions_{name}.jsonl")
        with open(out, "w") as f:
            for tx in txs:
                f.write(json.dumps(tx, separators=(",", ":"), sort_keys=True) + "\n")
        results[name] = txs
        print(f"[{name}] {len(txs)} txs -> {out} in {time.time()-t0:.1f}s", flush=True)

    a = {tx["txid"]: tx for tx in results["mempool"]}
    b = {tx["txid"]: tx for tx in results["blockstream"]}
    print(f"txid sets equal: {set(a) == set(b)}  mempool={len(a)} blockstream={len(b)}")
    only_a, only_b = set(a) - set(b), set(b) - set(a)
    if only_a: print(f"only in mempool ({len(only_a)}): e.g. {sorted(only_a)[:3]}")
    if only_b: print(f"only in blockstream ({len(only_b)}): e.g. {sorted(only_b)[:3]}")
    diffs = 0
    for t in sorted(set(a) & set(b)):
        ja, jb = a[t], b[t]
        cmp_keys = ("version", "locktime", "size", "weight", "fee")
        va = {k: ja.get(k) for k in cmp_keys}
        vb = {k: jb.get(k) for k in cmp_keys}
        sa, sb = ja.get("status", {}), jb.get("status", {})
        va["status"] = {k: sa.get(k) for k in ("confirmed", "block_height", "block_hash", "block_time")}
        vb["status"] = {k: sb.get(k) for k in ("confirmed", "block_height", "block_hash", "block_time")}
        va["vin"] = [(v.get("txid"), v.get("vout"), v.get("sequence")) for v in ja.get("vin", [])]
        vb["vin"] = [(v.get("txid"), v.get("vout"), v.get("sequence")) for v in jb.get("vin", [])]
        va["vout"] = [(v.get("scriptpubkey"), v.get("value")) for v in ja.get("vout", [])]
        vb["vout"] = [(v.get("scriptpubkey"), v.get("value")) for v in jb.get("vout", [])]
        if va != vb:
            diffs += 1
            if diffs <= 5:
                print(f"DIFF {t}:")
                for k in va:
                    if va[k] != vb[k]: print(f"  {k}: mempool={str(va[k])[:120]!r} blockstream={str(vb[k])[:120]!r}")
    print(f"content diffs on common txids: {diffs}")

    merged = dict(b); merged.update(a)   # mempool authoritative, blockstream fills gaps
    with open(os.path.join(BASE, "transactions.jsonl"), "w") as f:
        for t in sorted(merged):
            f.write(json.dumps(merged[t], separators=(",", ":"), sort_keys=True) + "\n")
    with open(os.path.join(BASE, "txids.txt"), "w") as f:
        for t in merged: f.write(t + "\n")
    n_conf = sum(1 for tx in merged.values() if tx.get("status", {}).get("confirmed"))
    print(f"merged: {len(merged)} unique txids ({n_conf} confirmed) -> transactions.jsonl, txids.txt")

if __name__ == "__main__":
    main()
