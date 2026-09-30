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

