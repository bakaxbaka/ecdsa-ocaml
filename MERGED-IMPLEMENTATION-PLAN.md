# Merged OCaml Bitcoin Analysis and Address Toolkit Plan

This document merges the two supplied implementation proposals into one
repository-aware roadmap. It preserves the useful SEC/BIP traceability while
separating the currently verified transaction-analysis work from future wallet
and address functionality.

## 1. Product boundary

The project has two related tracks:

1. **Auditable transaction analysis**
   - Parse Bitcoin transactions.
   - Extract and validate ECDSA signatures.
   - Compute legacy and BIP143 sighashes.
   - Detect evidence such as repeated `r` values.
   - Produce deterministic reports with provenance.

2. **Bitcoin key/address toolkit**
   - Encode public keys and hashes into P2PKH, P2SH-P2WPKH, P2WPKH, and P2TR
     addresses.
   - Add standards-compliant BIP32/BIP39/BIP44 functionality only after the
     primitive crypto and encoding layers are complete.
   - Provide scalar experiments only as explicitly labelled research tools.

The second track must not be presented as an extension of the first track's
security conclusions.

## 2. Current repository reality

Already present:

- typed secp256k1 field, scalar, curve, and ECDSA verification;
- strict DER parsing;
- SHA-256/hash256;
- Bitcoin transaction, script, legacy sighash, and BIP143 parsing;
- signature extraction and focused regression tests.

Not yet present:

- endomorphism modules;
- generic scalar derivation modules;
- RIPEMD-160/Hash160;
- Base58Check, Bech32, or Bech32m;
- Schnorr/Taproot;
- BIP32/BIP39/BIP44;
- transaction JSON scalar extraction;
- storage/database layer;
- application CLI.

The supplied Devin codemap describes some of these future capabilities, but it
is not evidence that they exist in this checkout.

## 3. Standards traceability

| Area | Standard | Planned responsibility |
| --- | --- | --- |
| Curve parameters and point encoding | SEC 2, SEC 1 §§2.2–2.3 | Existing curve layer and future key encoding |
| ECDSA verification | SEC 1 §4.1.4, FIPS 186-5 | Existing verification and analysis validation |
| Deterministic ECDSA nonces | RFC 6979 | Future signing support only |
| Legacy and SegWit transactions | Bitcoin transaction format, BIP143 | Existing parser and sighash layers |
| P2PKH/P2SH-P2WPKH | Bitcoin Core conventions, BIP49 | Future address modules |
| P2WPKH | BIP173/BIP84 | Future Bech32 address module |
| Schnorr signatures | BIP340 | Future Schnorr module |
| Taproot spending/address output | BIP341/BIP342/BIP350/BIP86 | Future Taproot and Bech32m modules |
| HD wallets | BIP32/BIP44 | Future wallet module |
| Mnemonic seeds | BIP39 | Future mnemonic module |

## 4. Phase A — Analysis foundation (complete)

Create `analysis/` with interface-first modules:

- `analysis_signature`: validated `(r, s), z` records plus transaction/input
  identity, public-key metadata, and sighash type;
- `finding`: typed findings with evidence and severity;
- `report`: deterministic summaries, provenance, and serialization;
- `nonce_checks`: repeated-`r`, duplicate vector, bounded small-value checks,
  and explicitly experimental relation checks.

Every constructor validates scalar ranges. Malformed inputs become typed
errors. No analysis function silently drops a candidate.

## 5. Phase B — Reproducible vector pipeline (complete)

Build an integration test over the supplied transaction package:

1. Hash source transaction files.
2. Parse each transaction.
3. Extract signatures and public keys.
4. Select legacy or BIP143 sighash according to transaction type.
5. Verify every signature.
6. Compare results with `ecdsa_vectors.csv`.
7. Emit a deterministic report.

The report must distinguish:

- verified facts;
- tests not applicable to the available data;
- hypotheses requiring private-key or side-channel evidence.

## 6. Phase C — Hash and encoding primitives

Implement and test in dependency order:

1. RIPEMD-160;
2. Hash160;
3. Base58;
4. Base58Check;
5. Bech32 witness encoding;
6. Bech32m;
7. WIF encoding/decoding;
8. tagged SHA-256 for BIP340/BIP341.

Use official BIP vectors and independent round-trip/property tests. Do not use
third-party web pages as the sole source of expected values.

## 7. Phase D — Public-key and address derivation

Add typed address modules:

- `bitcoin/address/p2pkh`;
- `bitcoin/address/p2sh_p2wpkh`;
- `bitcoin/address/p2wpkh`;
- `bitcoin/address/p2tr`.

Required invariants:

- compressed public keys are exactly 33 bytes and have prefix `02` or `03`;
- P2WPKH uses a 20-byte witness program and Bech32 version 0;
- P2TR uses a 32-byte x-only output key and Bech32m version 1;
- P2SH-P2WPKH hashes the witness program, not the public key directly;
- mainnet, testnet, and regtest prefixes/HRPs are explicit types, not booleans.

## 8. Phase E — Endomorphism and scalar research track

Add `crypto/curve/endomorphism` only after the existing scalar API is stable.
Test the identities:

- `lambda1 + lambda2 = -1 mod n`;
- `lambda1 * lambda2 = 1 mod n`;
- `lambda1^3 = 1 mod n`;
- `lambda2^3 = 1 mod n`.

If adding `derivation/`, keep operations in separate modules:

- unary;
- binary;
- ternary;
- polynomial;
- hash-based;
- bit-level;
- endomorphism-specific.

These are algebraic transformations, not wallet key derivation. They must not
be advertised as secure, collision-resistant, or suitable for recovering keys.
Every operation needs a combinatorial limit and a label describing its exact
formula.

## 9. Phase F — BIP32/BIP39/BIP44 wallet track

Implement only after address primitives:

- BIP39 checksum validation and PBKDF2-HMAC-SHA512;
- BIP32 master and child key derivation;
- hardened/non-hardened path validation;
- extended key serialization;
- BIP44 path policy.

Private material must remain in memory by default. Do not persist private keys
or mnemonics in SQLite without an explicit opt-in, encryption design, and
redaction policy.

## 10. Phase G — Extraction and storage

Add JSON extraction only for an explicitly declared input schema. Every
candidate should retain its JSON path and encoding provenance. Do not blindly
normalize every transaction integer into a private-key candidate.

Storage should begin with deterministic JSON/CSV exports. SQLite may follow
with versioned tables for:

- source transactions;
- extracted signatures;
- analysis findings;
- derived public addresses;
- target-address comparisons.

Store hashes and public metadata by default. Make private-key storage a
separate, disabled-by-default capability.

## 11. Phase H — CLI

Use Cmdliner with separate commands:

- `analyze-transaction`;
- `analyze-vectors`;
- `address-from-pubkey`;
- `wallet-derive` (later);
- `extract-candidates` (research-only, opt-in);
- `export-report`.

Each command needs:

- explicit input and output formats;
- bounded work limits;
- deterministic exit codes;
- human-readable and JSON output;
- diagnostics that identify the source field and failure.

Avoid one command that silently runs every scalar transform and address type.

## 12. Testing and release gates

- Unit tests for every public module.
- QCheck properties for encoding, parsing, scalar normalization, and reports.
- Official BIP vectors for addresses, BIP32, BIP39, Schnorr, and Bech32.
- Fuzz tests for DER, scripts, transactions, JSON, and encodings.
- Benchmarks at 60, 1k, 10k, and 100k records.
- CI for supported OCaml/Dune versions.
- `dune build`, `dune runtest`, formatting, and documentation checks.
- Threat model covering malformed inputs, resource exhaustion, secret exposure,
  and false-positive security claims.

## 13. Recommended implementation order

1. Complete the analysis API and vector pipeline.
2. Add RIPEMD-160, Hash160, Base58Check, and Bech32.
3. Add typed public-key/address derivation.
4. Add endomorphism identities as a separately labelled research module.
5. Add Schnorr and Taproot with official vectors.
6. Add BIP32/BIP39/BIP44.
7. Add bounded JSON extraction and public-result storage.
8. Add the CLI and release automation.

## Definition of done

The merged product is complete only when it can reproduce the supplied
transaction findings, derive standards-compliant public Bitcoin addresses,
validate official BIP vectors, enforce resource limits, protect secret
material, and clearly distinguish verified cryptography from experimental
scalar exploration.
