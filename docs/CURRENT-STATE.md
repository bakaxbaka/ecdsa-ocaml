# ecdsa-ocaml Current State Inventory

**Generated**: 2026-09-22  
**Project Version**: 0.1.0-alpha.1  
**Build System**: Dune 3.x  
**Language**: OCaml 4.14+

---

## Executive Summary

**Completion Status**: 35% by line count (estimated 10.7k / 28.5k LOC)

| Layer | Status | Completion | Test Coverage |
|-------|--------|-----------|----------------|
| `common/` | ✅ Complete | 100% | 0% (no tests) |
| `crypto/` | ✅ Complete | 100% | 60% |
| `bitcoin/` | ✅ Complete | 100% | 65% |
| `analysis/` | 🟡 Skeleton | 5% | 0% |
| `storage/` | ❌ Empty | 0% | N/A |
| `application/` | ❌ Empty | 0% | N/A |
| **Total** | 🟡 **Foundation** | **35%** | **40%** |

---

## Layer 0: `common/`

Foundation layer providing error families and shared utilities.

### Modules

| Module | File | LOC | Public API | Stability | Purpose |
|--------|------|-----|-----------|-----------|---------|
| `Error` | `error.ml` | ~80 | Parse_error, Der_error, Signature_error, Analysis_error | ✅ Frozen | Four error families for error ownership |
| `Common` | `common.ml` | ~5 | Re-exports | ✅ Frozen | Layer convenience re-export |

### Dependencies

- None (foundation)

### Tests

- ❌ No unit tests
- ✅ Error types are exercised by upper layers

### Notes

- Error types are interface-first, frozen for Phase 0–9
- All error variants carry descriptive context strings
- Fail-closed discipline: every error has a `to_string` method

---

## Layer 1: `crypto/`

Cryptographic primitives: field arithmetic, ECDSA, hashing.

### Modules Summary

| Module | File | LOC | Public API Symbols | Stability | Maturity |
|--------|------|-----|-------------------|-----------|----------|
| **Field** | `field/{field.ml,mli}` | ~110 | `t`, `make`, `add`, `mul`, `inv`, `of_z`, `to_z` | ✅ Frozen | 100% |
| **Scalar** | `scalar/{scalar.ml,mli}` | ~130 | `t`, `make`, `add`, `mul`, `inv`, `of_z`, `to_z` | ✅ Frozen | 100% |
| **Point** | `curve/{point.ml,mli}` | ~200 | `t`, `of_compressed`, `of_uncompressed`, `double`, `add`, `scalar_mult` | ✅ Frozen | 100% |
| **Signature** | `ecdsa/{signature.ml,mli}` | ~180 | `t`, `make`, `of_der`, `r`, `s`, `s_form`, `normalize_s` | ✅ Frozen | 100% |
| **DER** | `ecdsa/{der.ml,mli}` | ~250 | `parse`, `encode`, `strict_validate` (9 rules) | ✅ Frozen | 100% |
| **Verify** | `ecdsa/{verify.ml,mli}` | ~80 | `verify : pubkey -> z -> signature -> bool` | ✅ Frozen | 100% |
| **Hash** | `hash/{hash.ml,mli}` | ~120 | `sha256`, `sha256_double`, `hash256` | ✅ Frozen | 100% |
| **Hex** | `encoding/{hex.ml,mli}` | ~70 | `of_string`, `to_string` | ✅ Frozen | 100% |

### Dependencies

- `common/` — Error types
- External: `zarith`, `digestif`

### Tests

| Test Suite | Count | Status |
|-----------|-------|--------|
| DER parsing | 15 | ✅ Pass |
| Signature validation | 12 | ✅ Pass |
| Hash functions | 15 | ✅ Pass |
| Property tests (field, scalar, curve) | ~22 | ✅ Pass |
| **Total** | **~64** | ✅ **Pass** |

### Notes

- All arithmetic is modular (Field mod p, Scalar mod n)
- DER parser enforces 9 Bitcoin consensus rules
- Public-key verification and signature inspection are the supported analysis
  capabilities; optional research workflows remain explicitly scoped and
  opt-in

---

## Layer 2: `bitcoin/`

Bitcoin transaction parsing, script analysis, signature extraction.

### Modules Summary

| Module | File | LOC | Public API | Stability | Maturity |
|--------|------|-----|-----------|-----------|----------|
| **Types** | `transaction/types.ml` | ~280 | `transaction`, `txinput`, `txoutput`, `outpoint` | ✅ Frozen | 100% |
| **Parser** | `transaction/parser.ml` | ~400 | `of_hex : string -> transaction result` | ✅ Frozen | 100% |
| **Script** | `script/{script.ml,parser.ml,classify.ml}` | ~350 | `Script.t`, `parse`, `classify : script_type` | ✅ Frozen | 100% |
| **Sighash (Legacy)** | `sighash/legacy.ml` | ~220 | `compute : ... -> Z.t` | ✅ Frozen | 100% |
| **Sighash (BIP143)** | `sighash/bip143.ml` | ~180 | `compute : ... -> Z.t` | ✅ Frozen | 100% |
| **Sig Extraction** | `signature_extraction.ml` | ~300 | `extract : ... -> (Signature.t * Point.t) list result` | ✅ Frozen | 100% |

### Dependencies

- `common/`, `crypto/` — Error types, primitives

### Tests

| Test Suite | Count | Status |
|-----------|-------|--------|
| Transaction parsing | 24 | ✅ Pass |
| Script classification | 24 | ✅ Pass |
| Legacy sighash | 19 | ✅ Pass |
| BIP143 sighash | 15 | ✅ Pass |
| Signature extraction | 13 | ✅ Pass |
| Property tests (parsing) | ~10 | ✅ Pass |
| **Total** | **~105** | ✅ **Pass** |

### Notes

- Handles both legacy and SegWit transactions
- Script routing: P2PKH→Legacy, P2WPKH→BIP143
- All malformed inputs produce typed errors (fail-closed)

---

## Layer 3: `analysis/`

Signature observation, nonce analysis, finding detection. **Currently incomplete**.

### Modules Summary

| Module | File | Status | Completion | Tests |
|--------|------|--------|-----------|-------|
| **Observation** | `signature/observation.{ml,mli}` | 🟡 Partial | 70% | ❌ 0 |
| **Nonce** | `nonce/nonce.ml` | ❌ Skeleton | 5% | ❌ 0 |
| **Statistics** | `statistics/statistics.ml` | ❌ Skeleton | 5% | ❌ 0 |

### Current State

**Observation.build_observation** is 70% complete:
- ✅ Accepts transaction + metadata
- ✅ Extracts signatures via bitcoin/
- ✅ Routes sighash computation (legacy vs BIP143)
- ✅ Builds observation record
- ❌ No tests

**Nonce detectors are stubbed**:
- Function signatures exist
- Bodies return empty lists or `None`
- No actual analysis logic

**Finding types incomplete**:
- No `Finding.t` variant with severity/confidence
- No `Report.t` for aggregating findings
- No JSON/CSV serialization

### Dependencies

- `common/`, `crypto/`, `bitcoin/`

### Tests

- **0 tests** — Analysis layer is untested

### Next Steps (Phase 1)

1. Finalize `Finding.t` variant
2. Implement `Report.t` with provenance
3. Test `build_observation` end-to-end
4. Implement repeated-r detector
5. Add report serialization (JSON, CSV)

---

## Layer 4: `storage/`

❌ **Empty** — Interface and design not yet started.

### Estimated Effort

- 1,000–1,500 LOC
- Design: 1 week
- Implementation: 2–3 weeks

### Dependencies

- `analysis/` — Finding, Report types

---

## Layer 5: `application/`

❌ **Empty** — CLI and orchestration not yet started.

### Estimated Effort

- 1,200–1,800 LOC
- Design: 1 week
- Implementation: 2–3 weeks

### Dependencies

- `analysis/`, `storage/` — APIs

---

## Test Summary

| Layer | Unit | Property | Integration | Total | Status |
|-------|------|----------|-------------|-------|--------|
| `common/` | 0 | 0 | 0 | **0** | ❌ |
| `crypto/` | 42 | ~22 | 0 | **64** | ✅ |
| `bitcoin/` | 99 | ~10 | 0 | **109** | ✅ |
| `analysis/` | 0 | 0 | 0 | **0** | ❌ |
| **Total** | **141** | **~32** | **0** | **~173** | ✅ **40%** |

---

## Architecture Status

### Dependency Direction

```
common/ → crypto/ → bitcoin/ → analysis/ → storage/ → application/
```

✅ **Enforced** in Dune `(libraries ...)` clauses

### Type Safety

| Type | Module | Status |
|------|--------|--------|
| `Field.t` | `crypto/field/` | ✅ Distinct |
| `Scalar.t` | `crypto/scalar/` | ✅ Distinct |
| `Network.t` | `bitcoin/network/` | ✅ Enum |
| `Script_type.t` | `bitcoin/script/` | ✅ Enum |

---

## Build Status

```bash
$ dune build            # ✅ Pass
$ dune runtest          # ✅ 173 tests pass
$ dune build @fmt       # ✅ Formatted
$ dune build @doc       # ✅ Partial (70% doc comments)
```

---

## Known Gaps (Phase 0–9)

### Phase 0 Governance

- [ ] docs/ERROR-OWNERSHIP.md
- [ ] docs/SECURITY.md
- [ ] docs/INVARIANTS.md
- [ ] CI matrix (OCaml 4.14, 5.0, 5.1, 5.2)
- [ ] Version pinning in dune-project
- [ ] Layering enforcement script

### Phase 1 Analysis

- [ ] Finding.t variant
- [ ] Report.t with provenance
- [ ] Analysis tests

### Phase 2–9

- [ ] Nonce analysis detectors
- [ ] Hash functions (RIPEMD-160, Hash160, Bech32)
- [ ] Address derivation (P2PKH, P2WPKH, P2TR)
- [ ] Storage implementation
- [ ] CLI application
- [ ] Release gates

---

## Next Action

**Task #1 Complete**: docs/CURRENT-STATE.md written  
**Next Task #2**: Create docs/ERROR-OWNERSHIP.md
