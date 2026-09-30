# Error Ownership Model

**Purpose**: Define which layer owns which error category, ensuring fail-closed behavior and traceable error handling across the architecture.

**Date**: 2026-09-22  
**Version**: 1.0  
**Status**: Phase 0, Step 5

---

## Overview

Every error that can occur in ecdsa-ocaml belongs to one of four families, each owned by a specific layer. This document establishes:

1. **Error ownership** — which layer is responsible for each error type
2. **Error propagation** — how errors flow up the stack
3. **Fail-closed discipline** — every malformed input produces a typed error, never silent skip
4. **Actionability** — what a consumer should do when they receive each error

---

## Error Families & Layer Ownership

### Layer 0: `common/`

#### `Parse_error.t`

**Responsible layer**: `common/`  
**Raised by**: Every layer that parses untrusted input  
**Scope**: Byte-level encoding violations (bad hex, truncation, invalid prefix)

| Variant | Owner | Meaning | Action |
|---------|-------|---------|--------|
| `Bad_length` | Layer consuming bytes | Input length does not match expected format | Reject; log context (expected vs. actual) |
| `Bad_prefix` | Layer consuming bytes | First byte(s) do not match expected magic/type | Reject; byte value is corrupt or wrong format |
| `Bad_hex` | Encoding layer | Non-hex characters in hex string | Reject; invalid UTF-8 or non-hex digit |
| `Truncated` | Parser layer | Input ends prematurely during parsing | Reject; network corruption likely |
| `Trailing_data` | Parser layer | Unparsed bytes remain after parsing complete object | Reject; caller provided extra data |
| `Not_on_curve` | Curve layer | Point coordinates don't satisfy curve equation | Reject; point is invalid (possible forgery) |
| `Non_canonical` | Encoding layer | Multiple valid encodings exist; non-canonical chosen | Reject (BIP62 compliance); enforce low-S form |

**Propagation**: Raised by `crypto/encoding/`, `crypto/curve/`, `bitcoin/transaction/`, `bitcoin/script/` when decoding fails.

**Consumer action**:
- Log the full error context
- Return HTTP 400 (client error) in REST APIs
- Do NOT retry the same input
- Check for data corruption (hash input vs. transmitted value)

---

### Layer 1: `crypto/`

#### `Der_error.t`

**Responsible layer**: `crypto/ecdsa/`  
**Raised by**: DER parser (`crypto/ecdsa/der.ml`)  
**Scope**: DER-specific violations (invalid ASN.1 structure, out-of-range scalars)

| Variant | Owner | Meaning | Action |
|---------|-------|---------|--------|
| `Empty` | DER parser | Empty byte sequence provided | Reject; no signature present |
| `Not_a_sequence` | DER parser | Root tag is not `0x30` (SEQUENCE) | Reject; not a DER-encoded signature |
| `Bad_length` | DER parser | Length field encoding violates DER rules | Reject; malformed ASN.1 |
| `Not_an_integer` | DER parser | Expected INTEGER tag (`0x02`), got other | Reject; corrupted signature |
| `Negative_integer` | DER parser | INTEGER has sign bit set (0x00 prefix before 0x80–0xFF) | Reject; scalars must be non-negative |
| `Excessive_padding` | DER parser | Unnecessary 0x00 byte padding on r or s | Reject; non-canonical encoding (BIP62) |
| `Trailing_bytes` | DER parser | Extra bytes after s and sighash_type | Reject; extra data present |
| `Missing_sighash_byte` | DER parser | No sighash type byte at end | Reject; signature incomplete |
| `R_out_of_range` | DER parser | r < 1 or r ≥ n (secp256k1 order) | Reject; mathematically invalid signature |
| `S_out_of_range` | DER parser | s < 1 or s ≥ n | Reject; mathematically invalid signature |
| `High_s` | DER parser | s > n/2 (BIP62 low-S rule violated) | Reject (hard) or warn + normalize (soft, caller's choice) |

**Propagation**: Raised by `crypto/ecdsa/der.ml:parse()` and caught by `crypto/ecdsa/signature.ml:of_der()`.

**Consumer action**:
- `High_s` — Bitcoin Core enforces low-S; decide whether to normalize or reject
- All others — Reject without retry
- Log the specific error (helps forensics)
- May indicate signature tampering or malformed transaction

---

#### `Signature_error.t`

**Responsible layer**: `crypto/ecdsa/`  
**Raised by**: Signature construction and verification (`crypto/ecdsa/signature.ml`, `crypto/ecdsa/verify.ml`)  
**Scope**: Scalar validation, signature operations, key mismatches

| Variant | Owner | Meaning | Action |
|---------|-------|---------|--------|
| `Zero_r` | Signature builder | r component is 0 | Reject; scalar must be in [1, n-1] |
| `Zero_s` | Signature builder | s component is 0 | Reject; scalar must be in [1, n-1] |
| `Zero_nonce` | Signature creator | Nonce k generated as 0 (impossible in practice, but caught) | Reject; resample RNG |
| `Zero_private_key` | Signature creator | Private key d is 0 | Reject; key is invalid |
| `Non_invertible` | Field/Scalar ops | Value has no multiplicative inverse mod p/n | Reject; should never happen if inputs validated |
| `Verification_failed` | Verifier | ECDSA equation R ≠ r*G + z*Q does not hold | Reject; signature does not match pubkey + message |
| `Public_key_mismatch` | Verification module | The supplied pubkey does not match the signature context | Reject; mismatched data or invalid claim |

**Propagation**: Raised by `crypto/ecdsa/signature.ml:make()`, `crypto/ecdsa/verify.ml:verify()`, and error handler layers.

**Consumer action**:
- `Verification_failed` — Expected for mismatched keys or corrupted data; not an error condition in audit tools
- `Zero_*` — Indicates programming error (zero should have been caught at input); log and escalate
- `Non_invertible` — Should never occur; indicates data corruption or bug
- All others — Reject the operation; may indicate forgery attempt or data corruption

---

#### `Analysis_error.t`

**Responsible layer**: `analysis/` (research/inspection layer)  
**Raised by**: Optional analysis helpers that inspect signatures, nonces, or evidence bundles  
**Scope**: Explicitly scoped analysis failures when the evidence is incomplete or the assumptions are not met

| Variant | Owner | Meaning | Action |
|---------|-------|---------|--------|
| `Insufficient_evidence` | Analysis module | The input set does not support a conclusion | Reject; report the missing evidence |
| `Invalid_assumption` | Analysis module | Assumptions for the analysis are not satisfied | Reject; document the constraint |
| `Untrusted_input` | Analysis module | Provenance or metadata is missing or invalid | Reject; do not treat the result as evidence |
| `Ambiguous_result` | Analysis module | More than one explanation fits the observed data | Reject; require more evidence |

**Propagation**: Raised by optional analysis modules and surfaced through the analysis API with explicit assumptions and provenance.

**Consumer action**:
- Errors indicate that the analysis could not reach a defensible conclusion
- Return a typed failure rather than silently manufacturing a result
- Preserve provenance and clearly state the missing or invalid inputs

**Security note**: Optional analysis APIs must document their assumptions, preserve provenance, and report when evidence is insufficient.

---

### Layer 2: `bitcoin/`

#### `Signature_extraction.error` (no explicit error type yet; part of analysis layer design)

**Responsible layer**: `bitcoin/signature_extraction.ml`  
**Raised by**: Signature extraction from scriptSig and witness  
**Scope**: Script parsing failures, invalid DER in script, missing signatures

| Error Case | Handling | Action |
|------------|----------|--------|
| scriptSig is empty | Return empty list (valid for coinbase inputs) | OK; no signatures expected |
| scriptSig parse fails | Propagate `Parse_error` or `Der_error` | Reject transaction; invalid script |
| DER in scriptSig is invalid | Propagate `Der_error` | Reject signature extraction |
| Witness stack is empty | Return empty list (valid for non-SegWit) | OK; no witness signatures |
| Witness proof invalid | Propagate parse/DER error | Reject transaction |
| Script type unknown | Treat as no signatures | Log warning; continue analysis |

**Propagation**: Raised by `bitcoin/signature_extraction.ml` and propagated up through `analysis/signature/observation.ml:build_observation()`.

**Consumer action**:
- Return error to analysis layer with full context
- Analysis layer decides whether to fail transaction or skip input
- Log which script type caused extraction failure

---

### Layer 3: `analysis/`

#### `Observation.error` (to be defined in Phase 1)

**Responsible layer**: `analysis/signature/observation.ml`  
**Raised by**: Observation builder  
**Scope**: Transaction-to-observation conversion failures

| Error Case | Handling | Action |
|------------|----------|--------|
| Transaction parse fails | Propagate `bitcoin/` error with context | Reject transaction |
| Signature extraction fails | Propagate with input_index context | Fail transaction or skip input (configurable) |
| Sighash computation fails | Propagate `bitcoin/sighash/` error | Reject input; nonce computation impossible |
| Verification fails | Record as `ecdsa_valid = false` | OK; analysis continues (signature is invalid) |
| Script type unknown | Record `script_type = Unknown`, z = None | OK; observation incomplete but valid |

**Propagation**: Raised by `analysis/signature/observation.ml:build_observation()` when building fails.

**Consumer action**:
- If transaction fails → skip entire transaction, log error
- If input fails → skip that input, continue with others
- If verification fails → analysis continues (invalid signatures are data)
- If script type unknown → analysis continues (conservative approach)

---

### Layer 4: `storage/` (not yet implemented)

**Responsible layer**: `storage/` (future)  
**Scope**: Persistence, schema versioning, I/O

| Error Case | Handling |
|------------|----------|
| File not found | I/O error with path |
| Schema version mismatch | Migration error or version too old |
| Disk full | I/O error |
| Permission denied | I/O error with path |
| Corrupted JSON/CSV | Parse error with line number |
| Duplicate finding | Semantic error (should not occur) |

---

### Layer 5: `application/` (not yet implemented)

**Responsible layer**: `application/` (future, CLI)  
**Scope**: User input validation, resource limits, output formatting

| Error Case | Handling |
|------------|----------|
| File not found | User error; suggest correct path |
| Resource limit exceeded | User error; increase limit or reduce input size |
| Invalid command-line args | User error; show help |
| Output format invalid | Programmer error; report as bug |

---

## Error Flow Diagram

```
┌─ common/error.ml (4 families)
│
├─ crypto/ raises:
│   ├─ Parse_error → Encoding layer failures
│   ├─ Der_error   → DER parser failures
│   └─ Signature_error → Signature ops failures
│
├─ bitcoin/ raises:
│   ├─ Parse_error → Transaction/script parse failures
│   └─ Der_error   → Signature DER parse failures
│       (propagates from crypto/)
│
├─ analysis/ raises:
│   ├─ All above (propagated)
│   └─ Observation.error → (to be defined Phase 1)
│
├─ storage/ raises:
│   ├─ All above (propagated)
│   └─ Storage-specific errors (to be defined Phase 4)
│
└─ application/ raises:
    ├─ All above (propagated)
    └─ CLI-specific errors (to be defined Phase 5)
```

---

## Error Propagation Rules

### Rule 1: Never Catch and Ignore
```ocaml
(* ❌ WRONG *)
let _ = parse input in (* Error silently dropped *)
()

(* ✅ RIGHT *)
match parse input with
| Ok result -> process result
| Error e -> return_error e
```

### Rule 2: Fail Closed on Malformed Input
```ocaml
(* ❌ WRONG *)
if condition then parse input else default_value
(* Silently skips malformed input *)

(* ✅ RIGHT *)
parse input  (* Always validates; returns Error on malformed *)
```

### Rule 3: Preserve Error Context
```ocaml
(* ❌ WRONG *)
match parse input with
| Error _ -> Error "parse failed"  (* Context lost *)

(* ✅ RIGHT *)
match parse input with
| Error e -> Error (Printf.sprintf "parse failed: %s" (error_to_string e))
```

### Rule 4: Document Why Success is Optional
```ocaml
(* ✅ ACCEPTABLE (documented reason) *)
let z = match compute_sighash ~input_index in
| Ok z -> Some z
| Error _ -> None  (* Unknown script type; nonce unknown *)
(* Consumer sees z = None and understands why *)
```

### Rule 5: Experimental Analysis APIs Must Be Explicit
```ocaml
(* ✅ REQUIRED *)
(* Optional analysis must state its assumptions and keep the result typed. *)
match run_optional_analysis ~evidence with
| Ok result -> Ok result
| Error error -> Error error
```

---

## Error to HTTP Status Code Mapping (for REST APIs)

| Error Family | HTTP | Reason |
|--------------|------|--------|
| `Parse_error` | 400 Bad Request | Client provided malformed data |
| `Der_error` | 400 Bad Request | Invalid signature encoding |
| `Signature_error` | 400 Bad Request | Invalid signature values (zero, out of range) |
| `Verification_failed` | 422 Unprocessable Entity | Signature doesn't match pubkey/message (client issue) |
| `Analysis_error` | 400 Bad Request | Optional analysis could not reach a defensible conclusion |
| I/O error | 500 Internal Server Error | Server storage issue |
| Resource limit exceeded | 429 Too Many Requests | Client exceeded quota |

---

## Error Testing Requirements

Every error type must have at least one test case:

```ocaml
(* Example: test_der_error.ml *)

let test_der_r_out_of_range () =
  let invalid_der = 
    "\x30" (* SEQUENCE *)
    "\x08" (* length 8 *)
    "\x02\x01" (* INTEGER r, length 1 *)
    "\x00" (* r = 0, out of range *)
    "\x02\x02" (* INTEGER s, length 2 *)
    "\x00\x01" (* s = 1 *)
  in
  match Der.parse invalid_der with
  | Error Der_error.R_out_of_range -> assert_true "correctly rejected zero r"
  | Error _ -> assert_false "wrong error"
  | Ok _ -> assert_false "should have rejected"

(* Every variant of Der_error, Signature_error, etc. needs a test *)
```

---

## Checklist for Adding New Error Types

When a new error is needed:

- [ ] Add variant to appropriate error module in `common/error.ml`
- [ ] Add `to_string` case
- [ ] Document variant in this file with owner, scope, and action
- [ ] Add at least one test case (`test/unit/<layer>/test_errors.ml`)
- [ ] Update error flow diagram above
- [ ] Never propagate errors silently (always use Result)
- [ ] Never expose internal errors directly to CLI (wrap with context)

---

## Example: Error Handling in a Consumer Function

```ocaml
(* analysis/signature/observation.ml *)

let build_observation tx txid input_index spk_hint utxo_value =
  match Signature_extraction.extract ~tx ~input_index with
  | Error e ->
      Error (Extraction_error e)  (* Wrap and propagate *)
  | Ok signatures ->
      match compute_sighash ~script_type:(classify spk_hint) ~utxo_value with
      | Error e ->
          Error (Sighash_error e)  (* Wrap and propagate *)
      | Ok z ->
          let valid = Verify.verify ~pubkey:pk ~z ~sig_ in
          Ok {
            r = Signature.r sig_;
            s = Signature.s sig_;
            ecdsa_valid = Some valid;  (* Never fail on invalid sig *)
            (* ... *)
          }
```

---

## Related Documents

- **docs/CURRENT-STATE.md** — Inventory of which error families are currently in use
- **docs/SECURITY.md** — Threat model and error handling security assumptions
- **docs/INVARIANTS.md** — "Never silently skip" discipline and verification
- **MEGAPLAN.md** — Constraint 3 (Result, not exceptions) and Constraint 8 (no silent skip)

---

**Document Version**: 1.0  
**Last Updated**: 2026-09-22  
**Status**: ✅ Complete (Phase 0, Step 5)  
**Next**: docs/SECURITY.md (Phase 0, Step 8)
