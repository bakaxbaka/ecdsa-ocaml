# Invariants: Fail-Closed Discipline for ecdsa-ocaml

**Status**: Phase 0, Task #5  
**Version**: 1.0  
**Last Updated**: 2026-09-22  
**Owner**: Architecture team  

This document formalizes the non-negotiable invariants that govern ecdsa-ocaml. They are encoded in CI checks, code review, and automated tooling. Violations are **always failures**, never warnings or "acceptable deviations."

---

## Executive Summary

ecdsa-ocaml enforces **fail-closed discipline**: every error condition must be explicit, observable, and testable. There are no silent skips, implicit assumptions, or "best effort" semantics. Cryptographic correctness and reproducibility depend on this discipline.

The invariants are:

1. **Layering is unidirectional** (`common → crypto → bitcoin → analysis → storage → application`)
2. **Malformed input always produces an error** (no silent skips, truncations, or default values)
3. **All typed distinctions are enforced** (`Field.t ≠ Scalar.t ≠ Z.t`)
4. **Experimental analysis features are explicit and opt-in** (never silently activated, never advertised as required behavior)
5. **No `Obj.magic` in public APIs** (type safety cannot be bypassed)
6. **Result types for recoverable failures** (exceptions only for programmer errors)
7. **Every finding must be reproducible** (full provenance, deterministic, testable)
8. **Test vectors require explicit provenance** (source URL, hash, license, date)
9. **No secret material in logs** (private keys, nonces, sensitive values redacted)
10. **All output is deterministic** (no floating-point, no time-dependent behavior, no randomness)

Each invariant is supported by:

- **Automated enforcement** (CI checks, Dune build rules, linters)
- **Code review gates** (no merge without sign-off from layer owner)
- **Test coverage** (property tests, regression tests, fuzz tests)
- **Documentation** (this file, CONTRIBUTING.md, layer-specific READMEs)

---

## Invariant 1: Unidirectional Layering

### Statement

Dependencies flow **downward only**:

```
application/
     ↓
storage/
     ↓
analysis/
     ↓
bitcoin/
     ↓
crypto/
     ↓
common/
```

A layer **may depend only on layers below it**. Upward and circular dependencies are forbidden.

### Enforcement

- **Automated**: `tools/check-layering.sh` runs in CI and fails the build if any upward dependency is detected
- **Manual**: Code review requires architecture sign-off for any new `(libraries ...)` clause
- **Documentation**: Each layer's `dune` file lists permitted dependencies explicitly

### Current Dependencies (verified 2026-09-22)

| Layer | Permitted | Actual |
|-------|-----------|--------|
| `common/` | (none) | (none) |
| `crypto/field` | `common` | `zarith`, `common` ✓ |
| `crypto/scalar` | `common` | `zarith`, `common` ✓ |
| `crypto/curve` | `common`, `field`, `scalar` | `zarith`, `common`, `field`, `scalar` ✓ |
| `crypto/ecdsa` | `common`, `field`, `scalar`, `curve` | `zarith`, `common`, `field`, `scalar`, `curve` ✓ |
| `crypto/hash` | `common` | `digestif` ✓ |
| `crypto/encoding` | `common` | `common` ✓ |
| `bitcoin/transaction` | `common`, `crypto/encoding` | `common`, `encoding` ✓ |
| `bitcoin/script` | `common`, `crypto/encoding` | `common`, `encoding` ✓ |
| `bitcoin/sighash` | `common`, `crypto/encoding`, `bitcoin/transaction`, `bitcoin/script`, `crypto/hash` | `bitcoin_tx`, `encoding`, `hash` ✓ |
| `bitcoin/` (umbrella) | `common`, `crypto/*`, `bitcoin/*` | `common`, `encoding`, `bitcoin_tx`, `sighash`, `ecdsa_der`, `script_types` ✓ |
| `analysis/` (all) | `common`, `crypto/*`, `bitcoin/*` | (skeleton; will be verified in Phase 1) |
| `storage/` | `common`, `crypto/*`, `bitcoin/*`, `analysis/*` | (not yet implemented) |
| `application/` | all | (not yet implemented) |

**Action**: Run `check-layering.sh` before every merge. Automate this in CI.

---

## Invariant 2: Fail-Closed for Malformed Input

### Statement

Every parser, decoder, and validator must reject invalid input with an explicit error. There are no silent skips, truncations, default values, or "best effort" outputs.

Examples of violations (never do these):

```ocaml
(* WRONG: Silent skip *)
let parse_sig bytes =
  if String.length bytes < 70 then
    signature_default  (* WRONG: implicit default *)
  else
    parse_sig_strict bytes

(* WRONG: Silent truncation *)
let read_tx_output bytes offset =
  let value = read_u64_le bytes (offset + 1) in  (* ignore offset check *)
  (value, offset + 9)  (* proceeds even if offset was invalid *)

(* WRONG: Implicit zero *)
let parse_field_element hex =
  let z = Z.of_string_base 16 hex in
  Field.of_z_unsafe z  (* no validation that z < p *)
```

Examples of correct fail-closed behavior:

```ocaml
(* RIGHT: Explicit error *)
val parse_sig : bytes -> (signature, parse_error) result

(* RIGHT: Clear precondition check *)
let read_tx_output bytes offset : (tx_output * int, parse_error) result =
  if offset + 8 > Bytes.length bytes then
    Error (Parse_error.Insufficient_bytes {
      expected = offset + 8;
      got = Bytes.length bytes;
      context = "tx_output"
    })
  else
    (* parse and validate *)
    Ok (output, offset + 9)

(* RIGHT: Explicit boundary enforcement *)
let parse_field_element hex : (Field.t, parse_error) result =
  match Z.of_string_base 16 hex with
  | z when Z.geq z Field.p ->
      Error (Parse_error.Field_overflow {
        value = Z.to_string z;
        modulus = Z.to_string Field.p
      })
  | z -> Ok (Field.of_z z)
```

### Enforcement

- **Code review**: Every parser must have a test case that verifies rejection of invalid input (truncated, oversized, malformed)
- **Test suite**: Property tests verify that for every valid input, invalid variations are rejected
- **Fuzz testing**: Harnesses for DER, script, transaction, JSON parsers check that no input crashes the parser
- **Documentation**: `docs/ERROR-OWNERSHIP.md` defines which layer owns which error types

### Test Coverage

Each parser must have test cases for:

1. **Truncated input** (fewer bytes than required)
2. **Oversized input** (more bytes than expected)
3. **Malformed structure** (wrong magic bytes, invalid length, etc.)
4. **Boundary values** (maximum/minimum valid values, just-over limits)
5. **Field overflow** (scalars ≥ n, field elements ≥ p)
6. **Script recursion depth** (nested script with excessive depth)
7. **Transaction encoding** (invalid version, locktime, sequence numbers)

**Example test pattern** (from `test/unit/bitcoin/test_tx_parser.ml`):

```ocaml
let test_parse_truncated_input () =
  let bytes = Bytes.of_string "\x01\x00" in  (* version only, no inputs *)
  match Tx_parser.parse bytes with
  | Ok _ -> Alcotest.fail "Expected parse error for truncated tx"
  | Error err ->
      Alcotest.check string "error matches"
        "insufficient_bytes"
        (error_to_string err)

let test_parse_field_overflow () =
  let oversized_fe = String.make 32 '\xff' in  (* all 1 bits = p + ... *)
  match Field.of_bytes oversized_fe with
  | Ok _ -> Alcotest.fail "Expected field overflow error"
  | Error err ->
      Alcotest.check string "error matches"
        "field_overflow"
        (error_to_string err)
```

---

## Invariant 3: Typed Distinctions Are Enforced

### Statement

Type distinctions are **never bypassed**. The following are all distinct types:

- `Field.t` — integers modulo p (secp256k1 field modulus, 2^256 - 2^32 - 977)
- `Scalar.t` — integers modulo n (secp256k1 group order)
- `Z.t` — arbitrary-precision integers (used internally, never in public APIs)
- `Compressed_pubkey.t` — exactly 33 bytes, prefix 02 or 03
- `Xonly_pubkey.t` — exactly 32 bytes, no prefix
- `Network.t` — explicit variant (`Mainnet | Testnet | Regtest | Signet`), never a bool
- `Address_type.t` — explicit variant per BIP (P2PKH, P2SH, P2WPKH, P2WSH, P2TR)
- `Hash160.t`, `Hash256.t` — fixed-length hashes, not raw strings

### Anti-Pattern: Type Coercion via `Obj.magic`

```ocaml
(* WRONG: Never do this *)
let treat_field_as_scalar (fe : Field.t) : Scalar.t =
  Obj.magic fe  (* FORBIDDEN *)

(* WRONG: Implicit conversion *)
let add_field_and_scalar fe sc =
  let fe_as_z = Field.to_z fe in
  let sc_as_z = Scalar.to_z sc in
  let sum = Z.add fe_as_z sc_as_z in
  Field.of_z_unsafe sum  (* type error: forgot modulo n vs. p *)
```

### Correct Pattern: Explicit Type Conversion

```ocaml
(* RIGHT: Explicit, documented conversion with bounds check *)
val field_to_scalar : Field.t -> Scalar.t option
(* Converts field element to scalar if value < n.
   Returns None if conversion is undefined (value >= n). *)

(* RIGHT: No silent coercion *)
let add_field_and_scalar fe sc =
  match field_to_scalar fe with
  | Some sc' -> Scalar.add sc' sc
  | None -> Error "Field element too large for scalar arithmetic"
```

### Enforcement

- **Type system**: The OCaml type checker prevents most violations at compile time
- **Code review**: Any use of `Obj.magic`, `Unsafe`, or `_unsafe` suffix requires explicit justification and security sign-off
- **CI check**: `grep -r "Obj.magic" lib/ && echo "ERROR: Obj.magic not permitted in public APIs" && exit 1`
- **Test coverage**: Tests verify that coercion functions handle boundary cases correctly

---

## Invariant 4: Experimental Analysis Features Are Explicit and Opt-In

### Statement

Experimental analysis work is allowed only when it is clearly scoped, opt-in, and documented as non-default behavior. It must never be silently activated, and it must not be presented as current product functionality.

### Scope

Optional experimental analysis is out-of-scope for:

- Implicit certificate schemes (MQV, ECQV, PV) — **never implement**
- Wallet key derivation (BIP32, BIP39, BIP44) — use standard libraries
- X.509 certificate validation — not implemented
- Broad side-channel or research-only cryptanalysis tooling — not part of the project default scope

Optional experimental analysis is allowed when:

- The feature is explicitly labeled as research-only or exploratory
- Inputs, assumptions, and limitations are documented up front
- Results are deterministic and validated with reproducible fixtures
- The feature is isolated behind a clear public API or CLI flag and not silently enabled

### Implementation

```ocaml
(* In lib/analysis/analysis.mli *)

(** Optional analysis feature.
    Research-only: must be clearly scoped and never promoted as a runtime default.
    Results should be reproducible from input data and provenance metadata.
 *)

val run_experimental_analysis :
  input:analysis_input ->
  (analysis_report, analysis_error) result
(** This API is explicit and opt-in; it does not imply a product guarantee. *)
```

### Enforcement

- **Code review**: Experimental analysis features must be isolated behind explicit APIs or flags and clearly described in documentation
- **Documentation**: All opt-in analysis paths must document assumptions, limitations, and provenance requirements

---

## Invariant 5: No `Obj.magic` in Public APIs

### Statement

`Obj.magic` and other unsafe coercion functions are forbidden in `.mli` files and public module signatures. They may only appear:

1. In `.ml` files (implementation), with a comment explaining why
2. In `unsafe_` or `_unsafe` suffixed modules, with clear warnings
3. With explicit security review sign-off

### Rationale

`Obj.magic` bypasses the type system. Using it undermines the entire typed distinction enforcement (Invariant 3). If a type distinction is worth enforcing, it cannot be bypassed by magic.

### Examples

```ocaml
(* WRONG: Public API with Obj.magic *)
val coerce_to_field : 'a -> Field.t = Obj.magic
(* This defeats the point of having Field.t as a distinct type *)

(* RIGHT: Internal helper with clear why *)
(* In lib/crypto/field/field.ml *)
let of_z_unchecked z : Field.t =
  (* UNSAFE: Caller must ensure z < p.
     This is only for hot paths in arithmetic where the invariant
     is maintained by prior calls. *)
  Obj.magic z

(* RIGHT: Isolated unsafe module with warnings *)
(* lib/crypto/field/unsafe.mli *)
(** Unsafe field operations. Use only if you've proven preconditions.
    Violating preconditions produces silent corruption. *)

val of_z_unchecked : Z.t -> Field.t
(** No bounds checking. Returns garbage if z >= p. *)
```

### Enforcement

- **CI check**: `grep -r "Obj.magic" lib/**/*.mli && echo "ERROR" && exit 1`
- **Code review**: Any `Obj.magic` in `.ml` requires a comment starting with `(* UNSAFE:`
- **Audit trail**: Unsafe modules are listed in `SECURITY.md` under "Known Unsafe Patterns"

---

## Invariant 6: Result Types for Recoverable Failures

### Statement

Recoverable failures use `Result.t` or similar algebraic types. Exceptions are reserved for programmer errors only.

**Recoverable failures** (use `Result`):

- Input validation (malformed signature, oversized transaction, invalid encoding)
- Resource constraints (excessive recursion, oversized output)
- Missing data (key not found, transaction not in index)
- Cryptographic edge cases (invalid signature, nonce out of range)

**Programmer errors** (use exceptions):

- Violated preconditions (caller passed `Scalar.t` where `Field.t` required)
- Exhausted pattern matches (impossible case in case statement)
- Internal invariant violations (should never happen if code is correct)

### Examples

```ocaml
(* RIGHT: Result for recoverable *)
val parse_der_signature : bytes -> (Ecdsa_sig.t, der_parse_error) result

(* RIGHT: Result for resource constraint *)
val parse_script : bytes -> (script, script_error) result
(** Fails with Script_recursion_limit if nesting > 64. *)

(* RIGHT: Exception for programmer error *)
val field_of_scalar : Scalar.t -> Field.t
(** Raises Invalid_argument if scalar >= p. *)

(* WRONG: Exception for recoverable input error *)
val parse_signature : bytes -> Ecdsa_sig.t
(** Never do this. Use Result instead. *)
exception Parse_error of string
```

### Enforcement

- **Code review**: Any `raise` statement in `lib/*/` must have a comment explaining why it's a programmer error, not a recoverable failure
- **Linting**: `ocamlc -w +A-3` catches unused exceptions
- **Testing**: Catch all reachable `raise` statements in test coverage; they should be unreachable in normal code paths

---

## Invariant 7: Every Finding Must Be Reproducible

### Statement

Every security finding (repeated nonce, weak nonce, malformed signature, or other evidence-based signal) must be:

1. **Reproducible** from the same input, deterministically
2. **Auditable** with full provenance (source transaction, signature index, message hash)
3. **Testable** with automated test cases
4. **Documented** with standards reference (RFC, BIP, paper)

### Implementation

```ocaml
(* In lib/analysis/finding.mli *)

type finding = {
  kind : finding_kind;
  severity : severity;  (* critical, high, medium, low *)
  confidence : confidence;  (* certain, likely, possible *)
  message : string;
  provenance : provenance;  (* full audit trail *)
}

(* In lib/analysis/provenance.mli *)
type provenance = {
  source_tx : Hash256.t;  (* transaction ID *)
  input_index : int;  (* which input *)
  signature_index : int;  (* which signature in scriptSig *)
  pubkey : Compressed_pubkey.t;  (* which public key *)
  message_hash : Hash256.t;  (* what was signed *)
  extracted_at : string;  (* ISO 8601 timestamp *)
  analysis_version : string;  (* which version found this *)
}
```

### Test Pattern

```ocaml
(* In test/unit/analysis/test_finding.ml *)

let test_repeated_nonce_reproducible () =
  (* 1. Load same transactions *)
  let tx1 = load_test_vector "repeated_nonce_tx1.bin" in
  let tx2 = load_test_vector "repeated_nonce_tx2.bin" in
  
  (* 2. Run analysis twice *)
  let findings1 = analyze_transaction tx1 in
  let findings2 = analyze_transaction tx1 in
  
  (* 3. Verify findings are identical *)
  Alcotest.check (list finding) "findings are deterministic" findings1 findings2;
  
  (* 4. Verify provenance is complete *)
  List.iter (fun f ->
    assert (f.provenance.source_tx = tx1.id);
    assert (f.provenance.extracted_at <> "");
  ) findings1
```

### Enforcement

- **CI check**: All test vectors must have deterministic results (run twice, compare)
- **Code review**: New findings require test cases demonstrating reproducibility
- **Documentation**: Each finding type must have a reference to the standard or paper it comes from

---

## Invariant 8: Test Vector Provenance

### Statement

Every test vector file must have explicit provenance metadata:

- **Source URL** — where the vector came from
- **Source SHA-256** — hash of the original file at source
- **License** — how can the vector be used
- **Extracted at** — ISO 8601 date when vector was obtained
- **Extractor version** — which tool extracted it

### Format

```json
{
  "vectors": [
    {
      "file": "analysis/tx_vectors/ecdsa_vectors.csv",
      "source_url": "https://example.com/test_vectors/bitcoin_sigs.tar.gz",
      "source_sha256": "a1b2c3d4...",
      "license": "CC0",
      "extracted_at": "2026-09-15",
      "extractor_version": "bitcoin_extractor v1.0"
    }
  ]
}
```

Stored in `analysis/PROVENANCE.json`.

### Enforcement

- **CI check**: `tools/check-provenance.sh` verifies every `.csv`, `.json`, and binary vector has a manifest entry
- **CI gate**: Build fails if provenance is missing
- **Documentation**: `docs/VECTORS.md` lists all vectors and their sources

### Current Status

Provenance tracking is in `analysis/PROVENANCE.json` (manually maintained for Phase 0). Phase 1 will add automated provenance verification.

---

## Invariant 9: No Secret Material in Logs

### Statement

Private keys, secret nonces, intermediate values, and other sensitive material must never appear in:

- Standard output or error logs
- Test output
- Documentation
- Debug assertions
- JSON exports

### Implementation

```ocaml
(* In lib/common/redact.mli *)

(** Redact sensitive material from strings. *)
val redact_scalar : Scalar.t -> string
(** Returns "REDACTED(Scalar)" instead of printing the value. *)

val redact_field : Field.t -> string
(** Returns "REDACTED(Field)" instead of printing the value. *)

(* Usage in error messages *)
let verify_signature ~secret_key msg sig =
  match verify msg sig with
  | Ok () -> Ok ()
  | Error e ->
      (* WRONG: Error e |> sprintf "Signature failed for key %s" (Scalar.to_hex secret_key) *)
      (* RIGHT: *)
      Error (sprintf "Signature failed for key %s" (redact_scalar secret_key))
```

### Enforcement

- **Code review**: Every `Scalar.to_string`, `Field.to_string`, private key serialization must use `redact_*` helpers
- **Grep check**: `grep -r "to_hex\|to_string\|to_bytes" lib/ | grep -i "secret\|private" && echo "ERROR: secret material in log" && exit 1`
- **Test coverage**: Verify that error messages don't leak sensitive values

---

## Invariant 10: All Output Is Deterministic

### Statement

Analysis output, findings, and reports are **deterministic**. Given the same input transaction set and analysis version, the same output is produced every time.

No:

- Floating-point arithmetic (imprecise)
- Time-dependent behavior (timestamps in output that vary)
- Randomness (for analysis; randomness is allowed in key generation with explicit seeding)
- Hash-based iteration order (use sorted maps)

### Implementation

```ocaml
(* In lib/analysis/report.mli *)

type report = {
  findings : finding list;  (* sorted deterministically *)
  statistics : stats;
  generated_at : string;  (* ISO 8601, not wall-clock time *)
  tool_version : string;
  input_hash : Hash256.t;  (* hash of all inputs combined *)
}

(* Deterministic sorting *)
let sort_findings findings =
  List.sort (fun f1 f2 ->
    match compare f1.provenance.source_tx f2.provenance.source_tx with
    | 0 -> compare f1.provenance.input_index f2.provenance.input_index
    | c -> c
  ) findings
```

### Test Pattern

```ocaml
(* In test/unit/analysis/test_determinism.ml *)

let test_report_is_deterministic () =
  let input = load_test_transactions () in
  let report1 = generate_report ~seed:42 input in
  let report2 = generate_report ~seed:42 input in
  let json1 = Report.to_json report1 in
  let json2 = Report.to_json report2 in
  Alcotest.check string "reports are identical" json1 json2
```

### Enforcement

- **CI check**: Generate report twice, compare JSON output (must be byte-for-byte identical)
- **Code review**: Any time-dependent behavior (timestamps) must be injected as a parameter, not called at runtime
- **Property tests**: Run analysis on random transaction sets multiple times, verify consistency

---

## Enforcement Summary

| Invariant | Automated | Manual | Test Coverage |
|-----------|-----------|--------|---|
| 1. Layering | `check-layering.sh` in CI | Architecture review | Layering tests |
| 2. Fail-closed | Fuzz harnesses | Parser review | Invalid input tests |
| 3. Type distinctions | OCaml type system | `Obj.magic` grep | Coercion tests |
| 4. Recovery evidence | Evidence validation | Recovery review | Recovery evidence tests |
| 5. No `Obj.magic` | CI grep check | Code review | (compile-time) |
| 6. Result types | `raise` grep | Exception review | `Result` propagation tests |
| 7. Findings reproducible | Determinism tests | Findings review | `test_*_reproducible` suite |
| 8. Provenance | `check-provenance.sh` | Manifest review | Provenance validation tests |
| 9. No secrets in logs | Redaction helpers | Log review | Secret leak tests |
| 10. Deterministic output | Comparison tests | Output review | Determinism tests |

---

## Checklist for Code Review

Before merging any PR, verify:

- [ ] Layering check passes (`tools/check-layering.sh`)
- [ ] No upward or circular dependencies introduced
- [ ] All malformed input test cases pass
- [ ] No `Obj.magic` in `.mli` files
- [ ] All `raise` statements are commented as programmer errors
- [ ] New findings have reproducibility tests
- [ ] Test vectors have provenance entries
- [ ] No secret material in log output
- [ ] Analysis output is deterministic (run twice, compare)
- [ ] All tests pass (`dune runtest`)
- [ ] Code is formatted (`dune fmt`)
- [ ] Documentation builds (`dune build @doc`)

---

## Appendix: Invariant Violations and Remediation

### Case Study: Layering Violation

**Scenario**: Analysis layer adds a direct dependency on Application layer (circular).

**Detection**: `check-layering.sh` finds upward dependency.

**Fix**:
1. Identify the function that analysis needs from application
2. Move it down to a lower layer (storage or common)
3. Re-run `check-layering.sh` to verify fix
4. Update `.github/workflows/ci.yml` to run check after each commit

### Case Study: Silent Skip

**Scenario**: Transaction parser silently skips malformed outputs.

**Detection**: Fuzz test finds transaction that parses but should fail.

**Fix**:
1. Add explicit error case to `parse_error` type
2. Update parser to return error instead of skipping
3. Add test case for this malformed input
4. Re-run fuzz harness to verify no crashes

### Case Study: Type Coercion via Magic

**Scenario**: Developer uses `Obj.magic` to convert Field to Scalar.

**Detection**: CI grep check fails.

**Fix**:
1. Replace with explicit conversion function
2. Add test case for conversion boundary (value = n, value = n-1, etc.)
3. Document in code comment why conversion is needed
4. Security review sign-off before merge

---

## References

- `SECURITY.md` — Threat model and constraints
- `ERROR-OWNERSHIP.md` — Error family ownership and propagation
- `CONTRIBUTING.md` — Verification workflow and CI gates
- `.github/workflows/ci.yml` — Automated enforcement rules
- `tools/check-layering.sh` — Layering verification script
- `tools/check-provenance.sh` — Provenance validation script (TBD)

---

**Questions?** File an issue with the tag `[invariants]` or contact the architecture team.
