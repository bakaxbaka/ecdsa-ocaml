#!/usr/bin/env python3
"""gen_catalog.py — build TRANSACTION_CATALOG.md from cached chain data."""
import json, os, csv, collections, time, sys

HERE = os.path.dirname(os.path.abspath(__file__))
WB = os.path.dirname(HERE)
T = os.path.join(WB, "target")
ADDR = "17GGGHWtyi7e1rxnEpcKpE7fHq1UZBguAb"
TARGET_H160 = None
sys.path.insert(0, os.path.join(WB, "python"))
import btclib as B
TARGET_H160 = B.b58check_decode(ADDR)[1:].hex()

def btc(sats): return f"{sats/1e8:,.8f}"

def main():
    txs = {}
    for line in open(os.path.join(T, "transactions.jsonl")):
        t = json.loads(line)
        txs[t["txid"]] = t
    stats_m = json.load(open(os.path.join(T, "cache", "mempool_address.json")))
    stats_b = json.load(open(os.path.join(T, "cache", "blockstream_address.json")))
    assert stats_m["chain_stats"] == stats_b["chain_stats"]
    cs = stats_m["chain_stats"]
    inputs = list(csv.DictReader(open(os.path.join(T, "inputs.tsv")), delimiter="\t"))
    outputs = list(csv.DictReader(open(os.path.join(T, "outputs.tsv")), delimiter="\t"))
    sigs = list(csv.DictReader(open(os.path.join(T, "signatures.tsv")), delimiter="\t"))

    by_tx_in = collections.Counter(i["txid"] for i in inputs)
    tgt_in_per_tx = collections.Counter(i["txid"] for i in inputs if i["spends_target"] == "1")
    spend_txs = sorted(tgt_in_per_tx)

    rows = []
    for t in txs.values():
        st = t["status"]
        rows.append((st.get("block_height") or 10**9, st.get("block_time") or 0, t))
    rows.sort(key=lambda r: (r[0], r[1], r[2]["txid"]))

    years = collections.Counter(time.gmtime(r[1]).tm_year for r in rows if r[1])
    fund_vals = []
    for t in txs.values():
        v = sum(o["value"] for o in t["vout"] if o.get("scriptpubkey_address") == ADDR)
        fund_vals.append(v)

    L = []
    L.append("# TRANSACTION_CATALOG — 17GGGHWtyi7e1rxnEpcKpE7fHq1UZBguAb (bitcoin-mainnet)")
    L.append("")
    L.append(f"Generated: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} (UTC) from locally cached API data "
             f"(mempool.space + blockstream.info; raw hex authoritative).")
    L.append("")
    L.append("## Summary")
    L.append("")
    L.append("| metric | value |")
    L.append("|---|---|")
    L.append(f"| transactions (confirmed) | {cs['tx_count']} |")
    L.append(f"| mempool transactions | {stats_m['mempool_stats']['tx_count']} |")
    L.append(f"| funded TXOs (outputs to address) | {cs['funded_txo_count']} |")
    L.append(f"| total received | {btc(cs['funded_txo_sum'])} BTC |")
    L.append(f"| spent TXOs | {cs['spent_txo_count']} |")
    L.append(f"| total spent | {btc(cs['spent_txo_sum'])} BTC |")
    L.append(f"| balance | {btc(cs['funded_txo_sum']-cs['spent_txo_sum'])} BTC |")
    L.append(f"| unspent TXOs | {cs['funded_txo_count']-cs['spent_txo_count']} |")
    L.append(f"| first activity (block) | {rows[0][0]} ({time.strftime('%Y-%m-%d', time.gmtime(rows[0][1]))}) |")
    L.append(f"| last activity (block) | {rows[-1][0]} ({time.strftime('%Y-%m-%d', time.gmtime(rows[-1][1]))}) |")
    L.append(f"| total inputs across all txs | {len(inputs)} |")
    L.append(f"| total outputs across all txs | {len(outputs)} |")
    L.append(f"| ECDSA signatures extracted | {len(sigs)} |")
    L.append("")
    L.append("## Transactions per year (all 5,078)")
    L.append("")
    L.append("| year | txs |")
    L.append("|---|---|")
    for y in sorted(years):
        L.append(f"| {y} | {years[y]} |")
    L.append("")
    L.append("## All 29 spending transactions (inputs signed by the target key)")
    L.append("")
    L.append("These are the transactions whose inputs consume this address's UTXOs; they carry all 874 target signatures.")
    L.append("")
    L.append("| # | txid | height | time (UTC) | target inputs | total inputs | target input sum (BTC) | outputs | fee (BTC) | weight |")
    L.append("|---|---|---|---|---|---|---|---|---|---|")
    for k, txid in enumerate(spend_txs, 1):
        t = txs[txid]; st = t["status"]
        ti = [i for i in inputs if i["txid"] == txid and i["spends_target"] == "1"]
        tsum = sum(int(i["prevout_value"]) for i in ti if i["prevout_value"])
        L.append(f"| {k} | `{txid}` | {st.get('block_height')} | {time.strftime('%Y-%m-%d %H:%M', time.gmtime(st.get('block_time',0)))} | "
                 f"{len(ti)} | {len(t['vin'])} | {btc(tsum)} | {len(t['vout'])} | {t.get('fee',0)/1e8:.8f} | {t.get('weight')} |")
    tot_in = sum(int(i["prevout_value"]) for i in inputs if i["spends_target"] == "1" and i["prevout_value"])
    L.append("")
    L.append(f"Sum of all 874 target inputs: **{btc(tot_in)} BTC** — matches API `spent_txo_sum` "
             f"({btc(cs['spent_txo_sum'])} BTC): {tot_in == cs['spent_txo_sum']}.")
    L.append("")
    L.append("## First 25 transactions (chronological)")
    L.append("")
    L.append("| height | time | txid | value to target (BTC) | outputs | weight |")
    L.append("|---|---|---|---|---|---|")
    for h, bt, t in rows[:25]:
        v = sum(o["value"] for o in t["vout"] if o.get("scriptpubkey_address") == ADDR)
        L.append(f"| {h} | {time.strftime('%Y-%m-%d', time.gmtime(bt))} | `{t['txid']}` | {btc(v)} | {len(t['vout'])} | {t['weight']} |")
    L.append("")
    L.append("## Last 25 transactions (chronological)")
    L.append("")
    L.append("| height | time | txid | value to target (BTC) | outputs | weight |")
    L.append("|---|---|---|---|---|---|")
    for h, bt, t in rows[-25:]:
        v = sum(o["value"] for o in t["vout"] if o.get("scriptpubkey_address") == ADDR)
        L.append(f"| {h} | {time.strftime('%Y-%m-%d', time.gmtime(bt))} | `{t['txid']}` | {btc(v)} | {len(t['vout'])} | {t['weight']} |")
    L.append("")
    L.append("## Counterparties (top payers to this address)")
    L.append("")
    payer = collections.Counter()
    payer_val = collections.Counter()
    for t in txs.values():
        for vin in t.get("vin", []):
            po = vin.get("prevout") or {}
            a = po.get("scriptpubkey_address")
            if a and a != ADDR:
                payer[a] += 1
    for a, c in payer.most_common(10):
        L.append(f"- `{a}` — {c} inputs across the corpus")
    L.append("")
    L.append("## Output script-type distribution (all 30,448 outputs)")
    L.append("")
    L.append("| type | count |")
    L.append("|---|---|")
    for ty, c in collections.Counter(o["spk_type"] for o in outputs).most_common():
        L.append(f"| {ty} | {c} |")
    L.append("")
    L.append("## Machine-readable full catalog")
    L.append("")
    L.append("- `target/transactions.jsonl` — full API JSON for all 5,078 txs (vin/vout/status/fee/size/weight)")
    L.append("- `target/txids.txt` — 5,078 deduplicated txids")
    L.append("- `target/rawtx/<txid>.hex` — authoritative raw serialization for every tx (5,078 files)")
    L.append("- `target/rawtx_blockstream/<txid>.hex` — independent second-source hex (279 files, byte-identical)")
    L.append("- `target/inputs.tsv` (10,685 rows), `target/outputs.tsv` (30,448 rows)")
    L.append("- `target/signatures.tsv` (20,449 rows), `target/z_values.tsv` (20,449 rows)")
    L.append("")
    open(os.path.join(WB, "TRANSACTION_CATALOG.md"), "w").write("\n".join(L) + "\n")
    print("TRANSACTION_CATALOG.md written:", len(L), "lines")

if __name__ == "__main__":
    main()
