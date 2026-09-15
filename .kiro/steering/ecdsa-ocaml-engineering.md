---
inclusion: auto
name: ecdsa-ocaml-engineering
description: "Project-local Kiro Power for ecdsa-ocaml engineering workflow. Activates automatically when working on this OCaml cryptographic project."
---

## ecdsa-ocaml Engineering Power

This power enforces the architectural and engineering conventions of the ecdsa-ocaml OCaml cryptographic library.

### Core Responsibilities

This power helps with:

- OCaml 5.x development with Dune build system
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

### Architecture Rules

#### Dependency Direction

common -> crypto -> bitcoin -> analysis -> storage -> application

A layer may depend only on layers below it. Never introduce upward or circular dependencies.

#### Type Safety

Field and Scalar are different types:
- Field.t = integers modulo p (secp256k1 field modulus)
- Scalar.t = integers modulo n (secp256k1 group order)

Never replace both with Z.t in public APIs. Never use Obj.magic to bypass type distinctions.

#### Module Separation

Do NOT create monolithic modules. Separate curve subsystems.

### Verification Workflow

After any meaningful change:

1. Build the affected layer: opam exec -- dune build lib/<layer>
2. Build the entire project: opam exec -- dune build
3. Run tests: opam exec -- dune runtest
4. Format code (if relevant): opam exec -- dune fmt

If a command fails, report the actual compiler/test output.

### PowerShell File Writing

When writing OCaml source through PowerShell, use literal here-strings.

### Security Considerations

- Cryptographic code is security-sensitive
- Do not claim production security merely because tests pass
- Flag hand-written primitives as requiring extensive review before production
- Never expose secrets, private keys, or credentials in logs or test output