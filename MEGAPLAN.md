# ecdsa-ocaml Mega Plan

## Mission

Turn the current typed secp256k1 and Bitcoin parsing foundation into a
reproducible, auditable ECDSA analysis application without overstating what has
been verified.

The expanded merged roadmap is maintained in
[MERGED-IMPLEMENTATION-PLAN.md](./MERGED-IMPLEMENTATION-PLAN.md), combining the
transaction-analysis plan with the supplied address, wallet, encoding, and
CLI proposals.

## External codemap scope note

The shared Devin codemap, “secp256k1 Endomorphism & Key Derivation to Address
Encoding Pipeline,” describes an endomorphism/scalar-derivation/address
pipeline with modules such as `endomorphism.ml`, `unary.ml`, `binary.ml`,
`ternary.ml`, and Bech32/Hash160 encoding steps. Those modules are not present
in this checkout. The codemap is therefore treated as architectural input for a
possible future extension, not as evidence that those capabilities currently
exist or are verified.

If that pipeline is added later, it belongs after the current crypto foundation
and should be split into explicit modules:

- `crypto/curve/endomorphism` for constants and algebraic identities;
- `crypto/scalar/derivation` for typed, validated transformations;
- `bitcoin/address` for compressed public keys, Hash160, witness programs, and
  Bech32 encoding;
- independent property tests for each identity and encoding round trip.

Derived scalars must never be described as secure key derivation merely because
they are nonzero modulo the curve order. Any production key-derivation feature
needs a documented security construction, domain separation, and test vectors.

## Non-negotiable constraints

1. Preserve the dependency direction:
   `common -> crypto -> bitcoin -> analysis -> storage -> application`.
2. Keep public interfaces explicit and design `.mli` files before `.ml` files.
3. Return `Result` for recoverable failures; reserve exceptions for programmer
   errors.
4. Treat transaction reports as dataset evidence, not library guarantees.
5. Make every security conclusion reproducible from source data and tests.
6. Prefer deterministic, pure analysis functions.
7. Treat private-key recovery as a primary analysis objective; require explicit
   inputs, documented assumptions, and independent validation.
8. Never silently skip malformed signatures, transactions, or vectors.
9. Keep generated files and local tooling out of production library APIs.
10. Require build, test, formatting, and documentation checks before release.

## Phase 0 — Baseline and governance (complete)

- Freeze the current crypto/Bitcoin behavior with regression tests.
- Record supported OCaml, Dune, Zarith, Digestif, Alcotest, and QCheck versions.
- Define error ownership for each layer.
- Define test-vector provenance and integrity checks.
- Add CI for build, tests, formatting, and documentation.

## Phase 1 — Analysis domain model (complete)

- Introduce an `Analysis_signature` value containing `r`, `s`, `z`,
  public-key metadata, input index, transaction id, and sighash type.
- Validate scalar ranges at construction time.
- Add typed findings: repeated nonce, repeated `r`, weak nonce, relation,
  verification failure, and insufficient evidence.
- Add a report type with findings, counts, provenance, and confidence.
- Add stable pretty-printers and machine-readable serialization.

## Phase 2 — Deterministic nonce analysis (complete)

- Implement repeated-`r` detection.
- Implement repeated `(r, s)` and repeated full-vector detection.
- Implement configurable small-value checks without claiming nonce recovery.
- Implement affine/relation checks only when mathematically justified.
- Implement duplicate and cross-transaction correlation.
- Add complexity limits for large datasets.
- Add adversarial fixtures for every finding.

## Phase 3 — Vector package integration (complete)

- Parse the checked-in transaction hex files.
- Extract signatures with explicit malformed-data errors.
- Compute the correct legacy or BIP143 message hash.
- Verify each extracted signature against its public key.
- Compare generated vectors with `ecdsa_vectors.csv`.
- Store source hashes and extraction metadata.
- Fail closed when package claims and computed results disagree.

## Phase 4 — Storage (complete)

- Define a storage interface before selecting formats.
- Implement a deterministic JSON/CSV export.
- Add schema versioning and provenance fields.
- Add atomic writes and temporary-file cleanup.
- Add import validation and duplicate detection.
- Add migration tests for future schema changes.

## Phase 5 — Application and CLI (complete)

- Add a thin Cmdliner executable.
- Support transaction input from hex files and standard input.
- Support vector analysis from CSV/JSON.
- Emit human-readable and JSON reports.
- Return meaningful exit codes for invalid input, findings, and internal errors.
- Add bounded streaming/progress behavior for large datasets.

## Phase 6 — Security and quality

- Add property tests for parsers, encoders, and report serialization.
- Add fuzz tests for DER, scripts, transactions, and vector ingestion.
- Add performance tests for 60, 1k, 10k, and 100k signatures.
- Review integer widths, allocation behavior, and denial-of-service limits.
- Review all claims in README and analysis reports.
- Run documentation generation and resolve warnings.

## Phase 7 — Release

- Publish a reproducible test-vector manifest.
- Publish a threat model and limitations document.
- Verify clean builds from a fresh opam switch.
- Verify CI on supported OCaml versions.
- Review API stability and changelog entries.
- Tag only after all release gates pass.

## Definition of done

The project is complete only when a fresh checkout can parse the supplied
transactions, extract and verify the signatures, run the analysis, produce a
deterministic report, and explain every security conclusion with source data,
tests, and documented limitations.
