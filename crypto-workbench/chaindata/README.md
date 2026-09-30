# chaindata/ — persistence mirror of key target/ artifacts

The live working copies are under `target/` (excluded from workspace snapshots by
the generic `target` directory-name rule, hence this mirror). Contents:

- signatures.tsv      20,449 ECDSA signatures (all inputs of all 5,078 txs)
- z_values.tsv        reconstructed sighash z for every signature (dual-impl, verified)
- inputs.tsv          10,685 inputs with prevout metadata
- outputs.tsv         30,448 outputs with type/address
- anomalies.tsv       empty (header only) — zero anomalies
- schnorr_sigs.tsv    empty (header only) — no taproot inputs
- txids.txt           5,078 deduplicated txids
- transactions.jsonl  merged API metadata (mempool.space primary, blockstream.info gaps)
- verification.json   pipeline verification counters
- rawtx/<txid>.hex    authoritative raw serializations (5,078)
- preimages/          sighash preimages for all 874 target-key signatures

Regeneration (network): scripts/fetch_address.py, scripts/fetch_hex.py, scripts/parse_extract.py
