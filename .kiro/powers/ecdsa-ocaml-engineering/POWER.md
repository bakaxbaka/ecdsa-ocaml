---
name: "ecdsa-ocaml-engineering"
displayName: "ecdsa-ocaml Engineering"
description: "Project-local Kiro Power for safely developing, refactoring, testing, and maintaining this OCaml cryptographic project."
author: "Kiro"
keywords:
  - "ocaml"
  - "dune"
  - "ecdsa"
  - "secp256k1"
  - "cryptography"
  - "bitcoin"
  - "schnorr"
  - "sighash"
  - "crypto-analysis"
---

# ecdsa-ocaml Engineering

This power enforces the architectural and engineering conventions of the ecdsa-ocaml OCaml cryptographic library.

## When to Use This Power

Use this Power when working on tasks related to:

- OCaml/CamlLisp development with Dune build system
- secp256k1 elliptic curve cryptography implementation
- ECDSA signature creation, verification, and recovery
- Schnorr/BIP340 signature implementation
- Bitcoin transaction parsing and SIGHASH implementation
- Cryptographic test vector validation
- Property-based testing with QCheck
- Differential testing against reference implementations
- Safe refactoring of cryptographic code
- Repository state inspection before structural changes
- Architecture rule enforcement

## Core Responsibilities

This power helps with:

- **OCaml 5.x development** - Following OCaml idioms and best practices
- **Dune builds and tests** - Managing Dune project structure
- **Modular architecture enforcement** - Maintaining clean module boundaries
- **secp256k1 implementation** - Correct cryptographic primitives
- **ECDSA implementation and verification** - Mathematical correctness
- **Schnorr/BIP340 separation** - Proper signature scheme isolation
- **Bitcoin transaction and SIGHASH implementation** - Correct transaction processing
- **Cryptographic test vectors** - Validating against known values
- **Property-based testing** - QCheck properties for mathematical properties
- **Differential testing** - Comparing against trusted implementations
- **Safe refactoring** - Maintaining correctness during changes
- **Repository/state inspection** - Understanding actual project state before changes
- **Architecture rules** - Enforcing dependency direction and layer boundaries

## Architecture Rules

### Dependency Direction

```
common
   ↓
crypto
   ↓
bitcoin
   ↓
analysis
   ↓
storage
   ↓
application
```

A layer may depend only on layers below it. Never introduce upward or circular dependencies.

### Type Safety

**Field and Scalar are different types:**
- `Field.t` = integers modulo p (secp256k1 field modulus)
- `Scalar.t` = integers modulo n (secp256k1 group order)

Never replace both with `Z.t` in public APIs. Never use `Obj.magic` to bypass type distinctions.

### Module Separation

**Do NOT create monolithic modules.** Separate curve subsystems:

```
curve/
├── point.ml          (* representation only *)
├── point.mli
├── arithmetic.ml     (* operations: neg, add, double, scalar_mul *)
├── arithmetic.mli
├── secp256k1.ml      (* constants: a, b, generator *)
├── secp256k1.mli
├── serialization.ml  (* SEC1 encoding/decoding *)
└── serialization.mli
```

### Layer Boundaries

- **Crypto layer** = mathematical primitives only (no Bitcoin concepts)
- **Bitcoin layer** = transaction parsing, sighash, scripts
- **ECDSA** = mathematical operations on typed inputs
- **SIGHASH** = separate implementations for Legacy, BIP143, BIP341

## Testing Requirements

For every cryptographic primitive, test:

1. **Unit tests** - Basic functionality
2. **Known test vectors** - NIST, RFC, Bitcoin reference
3. **Property tests** (QCheck) - Mathematical properties
4. **Differential tests** - Compare against trusted implementation
5. **Integration tests** - End-to-end workflows

### Must-test invariants for secp256k1:
- `G is on curve`
- `nG = Infinity`
- `G + Infinity = G`
- `G + (-G) = Infinity`
- `double(G) = G + G`
- compressed/uncompressed serialization round trips
- invalid public keys are rejected

### Must-test for ECDSA:
- sign → verify round trip
- invalid signature rejection
- low-S normalization
- public-key recovery
- recovery-id handling

## Verification Workflow

After any meaningful change:

1. **Build the affected layer:**
   ```powershell
   opam exec -- dune build lib/<layer>
   ```

2. **Build the entire project:**
   ```powershell
   opam exec -- dune build
   ```

3. **Run tests:**
   ```powershell
   opam exec -- dune runtest
   ```

4. **Format code (if relevant):**
   ```powershell
   opam exec -- dune fmt
   ```

If a command fails, report the actual compiler/test output. Never claim success without running the commands.

## PowerShell File Writing

When writing OCaml source through PowerShell, use **literal here-strings**:

```powershell
@'
let example () =
  Error "Cannot invert zero"
'@ | Set-Content 'path\file.ml' -Encoding utf8 -NoNewline
```

Do NOT use expandable here-strings when the source contains `$` or backticks.

## Security Considerations

- Cryptographic code is security-sensitive
- Do not claim production security merely because tests pass
- Flag hand-written primitives as requiring extensive review before production
- Never expose secrets, private keys, or credentials in logs or test output

## Common Commands

```powershell
# Inspect project structure
Get-ChildItem -Recurse -Path d:\ecdsa-ocaml

# Build specific layer
opam exec -- dune build lib/common
opam exec -- dune build lib/crypto
opam exec -- dune build lib/bitcoin

# Build entire project
opam exec -- dune build

# Run tests
opam exec -- dune runtest

# Format code
opam exec -- dune fmt
```

## Context7 Integration

When API uncertainty exists, use the Context7 power to verify:
- OCaml standard library
- Dune build system
- Zarith big integer library
- QCheck property testing
- Alcotest unit testing
- Any other dependency

## License & Support

**License:** MIT

**Author:** Kiro
