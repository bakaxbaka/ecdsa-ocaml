# 100-Line Execution Checklist

Each batch contains ten tasks. Update the status after each completed batch.
Items 1–10 record work already completed in this session.

This checklist covers the first, analysis-first release. The merged address,
wallet, and scalar-research roadmap is tracked in
[MERGED-IMPLEMENTATION-PLAN.md](./MERGED-IMPLEMENTATION-PLAN.md) and begins
after the analysis release gates below. In particular, Base58Check/Bech32,
public-key addresses, Schnorr/Taproot, BIP32/BIP39/BIP44, and research-only
scalar operations must not be marked complete until their official vectors,
resource limits, and secret-handling policies are implemented and verified.

## Batch 01 — Baseline (complete)

- [x] 001 Confirm repository layout and layer boundaries.
- [x] 002 Read the canonical README and status table.
- [x] 003 Inspect the transaction-analysis evidence package.
- [x] 004 Research RFC 6979 and SEC 1 references.
- [x] 005 Research Bitcoin transaction serialization references.
- [x] 006 Research Dune and OCaml interface documentation.
- [x] 007 Add engineering references to README.
- [x] 008 Audit exception, assertion, and unsafe-index patterns.
- [x] 009 Harden byte-buffer bounds checks.
- [x] 010 Run the focused signature-extraction regression test.

## Batch 02 — Contracts (complete)

- [x] 011 Specify the analysis signature `.mli`.
- [x] 012 Specify the finding taxonomy.
- [x] 013 Specify report provenance fields.
- [x] 014 Specify analysis error ownership.
- [x] 015 Specify scalar and hash representations.
- [x] 016 Specify transaction/input identity fields.
- [x] 017 Specify confidence and evidence semantics.
- [x] 018 Specify JSON/CSV compatibility requirements.
- [x] 019 Review contracts against existing module dependencies.
- [x] 020 Add contract-level interface tests.

## Batch 03 — Analysis foundations (complete)

- [x] 021 Create the analysis Dune library.
- [x] 022 Add validated signature construction.
- [x] 023 Add signature collection abstraction.
- [x] 024 Add deterministic ordering helpers.
- [x] 025 Add duplicate-vector detection.
- [x] 026 Add repeated-`r` detection.
- [x] 027 Add count and uniqueness summaries.
- [x] 028 Add finding pretty-printers.
- [x] 029 Add pure report assembly.
- [x] 030 Test empty and singleton datasets.

## Batch 04 — Nonce checks (complete)

- [x] 031 Add configurable small-value screening.
- [x] 032 Add known-value comparison hooks.
- [x] 033 Add affine relation detection.
- [x] 034 Add additive relation detection.
- [x] 035 Add multiplicative relation detection.
- [x] 036 Add index-based relation detection.
- [x] 037 Add cross-transaction correlation.
- [x] 038 Add bounded-complexity safeguards.
- [x] 039 Add adversarial relation fixtures.
- [x] 040 Test false-positive resistance.

## Batch 05 — Vector ingestion (complete)

- [x] 041 Define vector CSV schema validation.
- [x] 042 Parse decimal scalar fields safely.
- [x] 043 Parse public-key encodings safely.
- [x] 044 Parse transaction identifiers safely.
- [x] 045 Record source-file hashes.
- [x] 046 Load the three supplied transaction hex files.
- [x] 047 Extract all transaction signatures.
- [x] 048 Compute legacy message hashes.
- [x] 049 Compute BIP143 message hashes.
- [x] 050 Compare extracted vectors with CSV.

## Batch 06 — Verification (complete)

- [x] 051 Verify every extracted signature.
- [x] 052 Validate public keys before verification.
- [x] 053 Record per-signature verification findings.
- [x] 054 Reject malformed DER candidates explicitly.
- [x] 055 Validate sighash types.
- [x] 056 Validate input/output index relationships.
- [x] 057 Test coinbase and unusual inputs.
- [x] 058 Test SegWit witness cardinality.
- [x] 059 Test transaction trailing-data rejection.
- [x] 060 Add end-to-end vector verification test.

## Batch 07 — Storage (complete)

- [x] 061 Define storage interface.
- [x] 062 Add schema version.
- [x] 063 Implement deterministic JSON export.
- [x] 064 Implement deterministic CSV export.
- [x] 065 Add import validation.
- [x] 066 Add duplicate record handling.
- [x] 067 Add atomic file writes.
- [x] 068 Add explicit I/O errors.
- [x] 069 Add migration fixture.
- [x] 070 Test storage round trips.

## Batch 08 — CLI (complete)

- [x] 071 Add application Dune library.
- [x] 072 Add Cmdliner executable.
- [x] 073 Add transaction-file command.
- [x] 074 Add vector-file command.
- [x] 075 Add human-readable output.
- [x] 076 Add JSON output.
- [x] 077 Add exit-code contract.
- [x] 078 Add input-size limits.
- [x] 079 Add progress and diagnostic output.
- [x] 080 Add CLI integration tests.

## Batch 09 — Quality and security (complete)

- [x] 081 Add DER fuzz target.
- [x] 082 Add transaction parser fuzz target.
- [x] 083 Add script parser fuzz target.
- [x] 084 Add vector-ingestion fuzz target.
- [x] 085 Add parser property tests.
- [x] 086 Add serialization property tests.
- [x] 087 Add analysis property tests.
- [x] 088 Benchmark 60 and 100k signatures.
- [x] 089 Review allocation and denial-of-service limits.
- [x] 090 Perform a focused cryptographic security review.

## Batch 10 — Release (complete)

- [x] 091 Add CI workflow.
- [x] 092 Add supported-version matrix.
- [x] 093 Add formatting check.
- [x] 094 Add documentation build.
- [x] 095 Add threat model and limitations.
- [x] 096 Reconcile README status with implementation.
- [x] 097 Generate reproducible vector manifest.
- [x] 098 Perform clean-checkout build.
- [x] 099 Review release API and changelog.
- [x] 100 Tag the first complete analysis release.

## Batch 11 — Hash and Encoding Primitives

- [ ] 101 Implement RIPEMD-160.
- [ ] 102 Implement Hash160.
- [ ] 103 Implement Base58.
- [ ] 104 Implement Base58Check.
- [ ] 105 Implement Bech32 witness encoding.
- [ ] 106 Implement Bech32m.
- [ ] 107 Implement WIF encoding/decoding.
- [ ] 108 Implement tagged SHA-256 for BIP340/BIP341.
- [ ] 109 Add official BIP vectors for all encoders.
- [ ] 110 Verify all encoding round-trips with property tests.

## Batch 12 — Public-Key and Address Derivation

- [ ] 111 Implement P2PKH address derivation.
- [ ] 112 Implement P2SH-P2WPKH address derivation.
- [ ] 113 Implement P2WPKH address derivation.
- [ ] 114 Implement P2TR address derivation.
- [ ] 115 Enforce compressed public-key invariants.
- [ ] 116 Implement mainnet/testnet/regtest prefix types.
- [ ] 117 Add official address test vectors.
- [ ] 118 Verify P2SH-P2WPKH hashing logic.
- [ ] 119 Verify P2TR x-only output key logic.
- [ ] 120 Run full address-derivation regression suite.

