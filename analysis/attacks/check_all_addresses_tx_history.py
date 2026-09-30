import csv
import json
import os
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

BASE_DIR = Path(r"D:\ecdsa-ocaml\analysis\attacks")
INPUT_PATH = BASE_DIR / "known_nonce_results_btc_addresses.txt"
CSV_PATH = BASE_DIR / "all_addresses_tx_history.csv"
SUMMARY_PATH = BASE_DIR / "all_addresses_tx_history_summary.txt"
STATE_PATH = BASE_DIR / "all_addresses_tx_history_state.json"
FIELDNAMES = [
    "address",
    "exists",
    "rows_in_dataset",
    "tx_count",
    "funded_txo_count",
    "spent_txo_count",
    "funded_txo_sum",
    "spent_txo_sum",
    "mempool_tx_count",
    "mempool_funded_txo_count",
    "mempool_spent_txo_count",
    "error",
]
ADDR_COLUMNS = [
    "legacy_uncompressed",
    "legacy_compressed",
    "p2sh_p2wpkh",
    "bech32_p2wpkh",
]


def load_unique_addresses():
    counts = {}
    with INPUT_PATH.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            for col in ADDR_COLUMNS:
                addr = (row.get(col) or "").strip()
                if addr:
                    counts[addr] = counts.get(addr, 0) + 1
    return counts


def load_state():
    if not STATE_PATH.exists():
        return {}
    try:
        with STATE_PATH.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(state):
    with STATE_PATH.open("w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)


def fetch_one(addr):
    url = "https://mempool.space/api/address/" + addr
    for attempt in range(5):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=20) as r:
                data = json.load(r)
            return {
                "address": addr,
                "exists": True,
                "rows_in_dataset": 0,
                "tx_count": int(data.get("chain_stats", {}).get("tx_count", 0) or 0),
                "funded_txo_count": int(data.get("chain_stats", {}).get("funded_txo_count", 0) or 0),
                "spent_txo_count": int(data.get("chain_stats", {}).get("spent_txo_count", 0) or 0),
                "funded_txo_sum": int(data.get("chain_stats", {}).get("funded_txo_sum", 0) or 0),
                "spent_txo_sum": int(data.get("chain_stats", {}).get("spent_txo_sum", 0) or 0),
                "mempool_tx_count": int(data.get("mempool_stats", {}).get("tx_count", 0) or 0),
                "mempool_funded_txo_count": int(data.get("mempool_stats", {}).get("funded_txo_count", 0) or 0),
                "mempool_spent_txo_count": int(data.get("mempool_stats", {}).get("spent_txo_count", 0) or 0),
                "error": "",
            }
        except urllib.error.HTTPError as exc:
            if exc.code in (429, 500, 502, 503, 504):
                wait = min(30, 2 ** attempt + 2)
                time.sleep(wait)
                continue
            return {
                "address": addr,
                "exists": False,
                "rows_in_dataset": 0,
                "tx_count": 0,
                "funded_txo_count": 0,
                "spent_txo_count": 0,
                "funded_txo_sum": 0,
                "spent_txo_sum": 0,
                "mempool_tx_count": 0,
                "mempool_funded_txo_count": 0,
                "mempool_spent_txo_count": 0,
                "error": f"HTTP {exc.code}",
            }
        except Exception as exc:
            if attempt < 4:
                time.sleep(2 ** attempt)
                continue
            return {
                "address": addr,
                "exists": False,
                "rows_in_dataset": 0,
                "tx_count": 0,
                "funded_txo_count": 0,
                "spent_txo_count": 0,
                "funded_txo_sum": 0,
                "spent_txo_sum": 0,
                "mempool_tx_count": 0,
                "mempool_funded_txo_count": 0,
                "mempool_spent_txo_count": 0,
                "error": f"{type(exc).__name__}: {exc}",
            }
    return {
        "address": addr,
        "exists": False,
        "rows_in_dataset": 0,
        "tx_count": 0,
        "funded_txo_count": 0,
        "spent_txo_count": 0,
        "funded_txo_sum": 0,
        "spent_txo_sum": 0,
        "mempool_tx_count": 0,
        "mempool_funded_txo_count": 0,
        "mempool_spent_txo_count": 0,
        "error": "unreachable",
    }


def load_or_init_rows():
    rows = []
    if CSV_PATH.exists():
        with CSV_PATH.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(row)
    return rows


def save_rows(rows):
    with CSV_PATH.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in FIELDNAMES})


def summarize(rows):
    all_rows = [r for r in rows if r.get("address")]
    active = [r for r in all_rows if r.get("exists") == "True" and (int(r.get("tx_count") or 0) or int(r.get("mempool_tx_count") or 0))]
    zero = [r for r in all_rows if r.get("exists") == "True" and not int(r.get("tx_count") or 0) and not int(r.get("mempool_tx_count") or 0)]
    missing = [r for r in all_rows if r.get("exists") != "True"]
    lines = [
        "Address transaction history check summary",
        f"Total unique addresses queried: {len(all_rows)}",
        f"Active / history present: {len(active)}",
        f"Zero-history addresses: {len(zero)}",
        f"Missing / unreachable: {len(missing)}",
        "",
        "Top active addresses:",
    ]
    for r in sorted(active, key=lambda r: (-int(r.get("tx_count") or 0), -int(r.get("rows_in_dataset") or 0), r.get("address", "")))[:20]:
        lines.append(
            f"{r['address']} | tx_count={r.get('tx_count')} | funded_txo_count={r.get('funded_txo_count')} | "
            f"spent_txo_count={r.get('spent_txo_count')} | rows_in_dataset={r.get('rows_in_dataset')}"
        )
    return "\n".join(lines) + "\n"


def main():
    counts = load_unique_addresses()
    unique = sorted(counts)
    if not unique:
        raise SystemExit("No addresses found in input file")
    rows_by_addr = {r["address"]: r for r in load_or_init_rows()}
    remaining = [addr for addr in unique if addr not in rows_by_addr]
    print(f"Unique addresses: {len(unique)}")
    print(f"Already processed: {len(rows_by_addr)}")
    print(f"Remaining: {len(remaining)}")

    state = load_state()
    if state:
        remaining = [addr for addr in remaining if addr not in state.get("done", set())]

    batch_size = 250
    processed_count = 0
    for i in range(0, len(remaining), batch_size):
        batch = remaining[i:i + batch_size]
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(fetch_one, addr) for addr in batch]
            for fut in as_completed(futures):
                result = fut.result()
                address = result["address"]
                result["rows_in_dataset"] = counts.get(address, 1)
                rows_by_addr[address] = result
                processed_count += 1
                if processed_count % 25 == 0:
                    save_rows([rows_by_addr[a] for a in sorted(rows_by_addr)])
                    print(f"Progress: {processed_count}/{len(remaining)} addresses fetched")
                time.sleep(0.1)

        save_rows([rows_by_addr[a] for a in sorted(rows_by_addr)])
        save_state({"done": list(rows_by_addr.keys())})
        print(f"Completed batch {i // batch_size + 1}/{(len(remaining) + batch_size - 1) // batch_size}")

    ordered = [rows_by_addr[a] for a in sorted(rows_by_addr)]
    save_rows(ordered)
    SUMMARY_PATH.write_text(summarize(ordered), encoding="utf-8")
    print(f"All done. Wrote {len(ordered)} rows to {CSV_PATH}")
    print(f"Summary saved to {SUMMARY_PATH}")


if __name__ == "__main__":
    main()
