# TARGET_REPORT — bitcoin-mainnet address forensics

| field | value |
|---|---|
| target address | `17GGGHWtyi7e1rxnEpcKpE7fHq1UZBguAb` (P2PKH, mainnet) |
| retrieval timestamps (UTC) | address stats 2026-09-25T02:49:40Z; tx history complete 03:05:17Z; raw hex complete ~03:20Z; analysis 2026-09-25T04:17:16Z |
| API sources | mempool.space (primary), blockstream.info (cross-check); btc1.trezor.io unreachable (Cloudflare bot-wall on datacenter IP — evidence cached) |
| transactions fetched | 5078 confirmed + 0 mempool (complete history; paging until empty) |
| cross-source agreement | txid sets identical; 0 content diffs (version/locktime/size/weight/fee/status/vin/vout) |
| raw tx hex cached | 5078/5078 (mempool.space); 279 byte-identical second-source copies (blockstream.info); 0 mismatches |
| structural verification | 5078/5078: reserialization byte-identical, txid=dSHA256(serialized), wtxid, size, weight all match |
| total inputs parsed | 10685 (0 coinbase among them) |
| total outputs parsed | 30448 |
| ECDSA signatures extracted | 20449 (all inputs of all txs) |
| signatures by target key | 874 (= spent_txo_count 874 — exact reconciliation) |
| target public key | `03507a40492642239fc7eae74bc1f1beb15a6079ea3702cfdaeec2268bb00bcbd0` (compressed; HASH160 → address matches target) |
| schnorr/taproot inputs | 0 |
| balance | 2,785.11802343 BTC (4176 UTXOs) |
| total received / spent | 4,896.58524364 / 2,111.46722021 BTC |
| address activity window | blocks 437639–967971 (2016-11-06 → 2026-09-21) |
| target-key signing window | blocks 452042–967971 (2017-02-08T03:48:42Z → 2026-09-21T09:33:30Z), 29 consolidation txs |

## Script types

- inputs by prevout type: {"p2sh": 9764, "p2wpkh": 23, "p2pkh": 898}
- target-key inputs: 874/874 P2PKH (legacy sighash)
- outputs by type: {"p2pkh": 21043, "p2sh": 8798, "p2wpkh": 597, "p2wsh": 5, "op_return": 5}

## Sighash types

- distribution over all 20449 signatures: `0x01 SIGHASH_ALL` × 20449 (100%); no ANYONECANPAY/NONE/SINGLE observed.

## Signature parsing failures

- DER parse failures: 0. Non-canonical DER re-encodings: 0. Anomalies file rows: 0.
- High-S signatures: 0 (100% BIP147 low-S compliance).

## z reconstruction

- method: legacy pre-segwit SignatureHash for P2PKH/P2SH inputs; BIP143 for segwit inputs (23 P2WPKH).
- success: 20449/20449 signatures (100%); failures: 0. z NEVER taken from txid.
- implementations: btclib (primary) + sighash_alt (independent) → disagreements: 0.
- preimages for all 874 target signatures archived: target/preimages/.

## Cross-validation results (independence chain)

| check | engine | result |
|---|---|---|
| preimage/sighash bytes vs official BIP143 vectors (incl. all 6 sighash types, P2WPKH/P2SH-P2WPKH/P2SH-P2WSH, legacy P2PK, SINGLE-bug) | tests/test_sighash_vectors.py | 40/40 |
| z agrees between two independent implementations | btclib vs sighash_alt | 20449/20449 |
| ECDSA verify with reconstructed z | OpenSSL (cryptography lib) | 20449/20449 |
| ECDSA verify with reconstructed z (target set + samples) | pure-python secp256k1 | 1864/1864 |
| ECDSA verify (target set + 150 sampled others) | PARI/GP ellmul | 1024/1024, 0 disagreements |
| prevout value/scriptPubKey of every target input | re-derived from prevout tx raw hex (not API JSON) | 874/874, 0 mismatches |
| API JSON vs raw-hex parse (values, spks, sizes, weights, txids) | parse_extract.py | 0 mismatches |
| second-source raw hex bytes | mempool vs blockstream (279 txs incl. all 29 spenders) | 0 mismatches |

## Repeated-input patterns

- 874 target inputs across 29 consolidation transactions; every input spends a distinct parent tx (874 distinct parents, 0 repeated).
- prevout output-index distribution: {"1": 614, "2": 179, "3": 75, "0": 6} (deposits typically land at vout 1–3).
- sequence values: {"fffffffd": 629, "ffffffff": 245} (fffffffd = RBF-signalling, ffffffff = final).
- inputs per spending tx: min 3, max 123 (large fan-in consolidations).

## Repeated-value patterns

- input values: only 25 distinct amounts across 874 inputs — highly repeated denominations:
  2.0950 BTC×208, 2.9950 BTC×183, 4.4950 BTC×159, 2.9967 BTC×90, 0.1483 BTC×47, 0.8950 BTC×41
- output values (spending txs): round-lot dominated: 100.00 BTC×14, 50.00 BTC×5, 3.38 BTC×3, 1.90 BTC×3, 40.00 BTC×3
- no change outputs return to the target address (0 of 57).
- pattern (many fixed-denomination deposits → few round-lot outbound payments, no change back) is characteristic of a custodial/exchange-style collection wallet. This is a behavioural observation, not an attribution.

## Detected anomalies

- anomalies.tsv rows: 0 (none).
- r reuse: 0 groups among target sigs; 0 among all 20449 sigs (1201 distinct pubkeys).
- (r,s) reuse: 0 (target), 0 (all).
- statistical detail in SIGNATURE_ANALYSIS.md; headline: r/s/z pass uniformity tests (KS p = 0.7528, 0.5291, 0.7084).

## Conclusion

Complete history retrieved and byte-verified; all parsable signatures extracted; z reconstructed for 100% and
independently validated by four engines. **No nonce reuse, no encoding anomalies, no statistically detectable
nonce bias** — nothing in the public data indicates an exploitable weakness. All failures encountered during the
run were engineering issues (fixed and logged in logs/fixes.log); none touched data integrity.

_Security note: this report contains only public blockchain data. No private keys were derived, requested, or
stored at any point; duplicate-r screening is reported as a detection result only._
