# Contributing to ecdsa-ocaml

Thank you for your interest in contributing to ecdsa-ocaml!

## Development Setup

### Prerequisites

- OCaml 4.14+ (tested on 4.14, 5.0, 5.1, 5.2)
- Dune 3.0+ (build system)
- opam (OCaml package manager)

### Quick Start

```bash
# Install OCaml and opam (if not already installed)
# Follow: https://ocaml.org/docs/installing-ocaml

# Create a fresh opam switch (recommended)
opam switch create ecdsa-ocaml ocaml.5.1

# Install dependencies
opam install -y dune zarith digestif alcotest qcheck yojson ocamlfind merlin

# Clone and build
git clone https://github.com/your-org/ecdsa-ocaml.git
cd ecdsa-ocaml
opam exec -- dune build
opam exec -- dune runtest
```

## Verification Workflow

After any meaningful change, run these commands in order:

```bash
# 1. Build affected layer
opam exec -- dune build lib/<layer>

# 2. Build entire project
opam exec -- dune build

# 3. Run all tests
opam exec -- dune runtest

# 4. Format code
opam exec -- dune fmt

# 5. Build documentation
opam exec -- dune build @doc
```

**Never push without running these checks!**

## CI Gates (Automated)

The CI pipeline runs automatically on every push and PR. It verifies:

- ✅ **Build** — `dune build` succeeds on Ubuntu, macOS, Windows
- ✅ **Tests** — `dune runtest` passes (173+ tests)
- ✅ **Formatting** — `dune build @fmt` passes (code style)
- ✅ **Documentation** — `dune build @doc` builds (API docs)
- ✅ **Security** — No `Obj.magic` in public APIs
- ✅ **Reproducibility** — Two builds produce identical artifacts
- ✅ **Layering** — No upward dependencies between layers

CI runs on matrix:
- **OCaml**: 4.14, 5.0, 5.1, 5.2
- **Dune**: 3.0, 3.1, 3.2, 3.3
- **OS**: Linux (ubuntu-latest), macOS (macos-latest), Windows (windows-latest)

See `.github/workflows/ci.yml` for details.

## Code Style

### Formatting

Use ocamlformat (automatic via `dune fmt`):

```bash
opam exec -- dune fmt
```

Configuration in `.ocamlformat`:
- Margin: 100 characters
- Indent: 2 spaces
- Profile: default

### Naming Conventions

- **Modules**: `snake_case` (e.g., `signature_extraction.ml`)
- **Types**: `snake_case` (e.g., `type t`, `type s_form`)
- **Functions**: `snake_case` (e.g., `parse_der`, `verify_signature`)
- **Variables**: `snake_case` (e.g., `let r_value = ...`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `let SECP256K1_N = ...`)
- **Type aliases**: `snake_case` (e.g., `type error_context = string`)

### Comments

- **Module-level**: `(** ... **)` doc comments (required for .mli files)
- **Type definitions**: Explain the invariant
- **Functions**: Explain parameters, return value, and error conditions
- **Inline**: Only for non-obvious logic

Example:

```ocaml
(** Parse a DER-encoded ECDSA signature.
    
    Enforces 9 Bitcoin consensus rules:
    - No leading zeros in r or s
    - r and s must be in [1, n-1]
    - ... (full list)
    
    Returns [Error] if any rule is violated.
    Never silently skips malformed input.
 *)
val parse : bytes -> (parsed, Der_error.t) result
```

## Type Safety

### Layer-Specific Types (DO NOT MIX)

```ocaml
(* ❌ WRONG: mixing Field.t and Scalar.t *)
let x : Field.t = Scalar.make big_int |> Obj.magic

(* ✅ RIGHT: use distinct types *)
module Field : sig type t end
module Scalar : sig type t end
let x : Field.t = Field.make big_int
let y : Scalar.t = Scalar.make big_int
```

### Result Types (Fail Closed)

```ocaml
(* ❌ WRONG: silently skipping errors *)
match parse input with
| Error _ -> default_value

(* ✅ RIGHT: propagate error *)
match parse input with
| Ok result -> process result
| Error e -> Error (wrap_error e)
```

## Testing Requirements

Every new feature or fix must include tests.

### Unit Tests

- Location: `test/unit/<layer>/test_<module>.ml`
- Framework: Alcotest
- Coverage: Minimum 2 test cases per function

Example:

```ocaml
let test_parse_valid_der () =
  let valid_der = ... in
  match Der.parse valid_der with
  | Ok parsed -> Alcotest.check z "r matches" expected_r parsed.r
  | Error _ -> Alcotest.fail "should have parsed"

let test_parse_invalid_der_r_out_of_range () =
  let invalid_der = ... in
  match Der.parse invalid_der with
  | Error Der_error.R_out_of_range -> ()
  | _ -> Alcotest.fail "should reject out-of-range r"

let () =
  Alcotest.run "Der" [
    ("valid DER", [ Alcotest.test_case "parse" `Quick test_parse_valid_der ]);
    ("invalid DER", [ Alcotest.test_case "r out of range" `Quick test_parse_invalid_der_r_out_of_range ]);
  ]
```

### Property-Based Tests

- Location: `test/property/<layer>/prop_<module>.ml`
- Framework: QCheck
- Coverage: Test invariants, round-trips, equivalences

Example:

```ocaml
let prop_field_add_commutative =
  QCheck.Test.make ~count:10000
    (QCheck.pair QCheck.printable_int QCheck.printable_int)
    (fun (a, b) ->
      let fa = Field.make (Z.of_int a) |> Result.get_ok in
      let fb = Field.make (Z.of_int b) |> Result.get_ok in
      Field.equal (Field.add fa fb) (Field.add fb fa))
```

### Fixture Files

- Location: `test/vectors/<layer>/` or `test/fixtures/<layer>/`
- Format: Hex files, CSV, JSON
- Documentation: Add README explaining each fixture

## Architecture Rules (Non-Negotiable)

### Dependency Direction

```
common → crypto → bitcoin → analysis → storage → application
```

**Rule**: Only depend on layers **below**. Never upward or circular.

**Enforcement**: CI checks via `tools/check-layering.sh` (Phase 0, Step 10).

### Module Separation

**Rule**: One module per subsystem, each with `.mli`.

**Good** (separate modules):
- `crypto/field/` — Field.t arithmetic
- `crypto/scalar/` — Scalar.t arithmetic
- `bitcoin/sighash/legacy.ml` — Legacy sighash
- `bitcoin/sighash/bip143.ml` — BIP143 sighash

**Bad** (monolithic):
- `crypto/arithmetic.ml` — Field AND Scalar together
- `bitcoin/sighash.ml` — Legacy AND BIP143 together

## Error Handling

Every error must be **typed** and **contextual**. See `docs/ERROR-OWNERSHIP.md`.

```ocaml
(* ❌ WRONG: string error, no context *)
Error "parse failed"

(* ✅ RIGHT: typed error with context *)
Error (Printf.sprintf "DER: r out of range [1, %s], got %s"
  (Z.to_string (Z.pred secp256k1_n))
  (Z.to_string r))
```

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): subject

body (optional)

footer (optional)
```

Examples:

```
feat(crypto/ecdsa): add Schnorr signature verification

Add BIP340 Schnorr signature verification against secp256k1 keys.
Includes 15 test vectors from BIP340.

Closes #123
```

```
fix(bitcoin/sighash): correct BIP143 sequence hashing

The sequence number was being hashed twice. Fixed to hash once as per BIP143.

Fixes #456
```

## Pull Request Checklist

- [ ] Code follows style guide (`dune fmt` passes)
- [ ] Tests added/updated for new functionality
- [ ] All tests pass (`dune runtest`)
- [ ] Documentation updated (README, docs/*, .mli comments)
- [ ] No `Obj.magic` in public APIs
- [ ] Error handling is typed (Result types, not exceptions)
- [ ] Commit messages follow Conventional Commits
- [ ] No breaking changes without discussion
- [ ] Related issues referenced in PR description

## Reporting Issues

### Security Vulnerabilities

**Do NOT create a public GitHub issue.** Instead:

1. Email security contact (see SECURITY.md)
2. Include:
   - Description of vulnerability
   - Steps to reproduce
   - Suggested fix (if available)
   - Expected disclosure timeline (default: 90 days)

### Bugs

Create an issue with:

```
## Description
Brief summary of the bug.

## Reproduction Steps
1. ...
2. ...

## Expected Behavior
What should happen.

## Actual Behavior
What actually happens.

## Environment
- OCaml version: (output of `ocamlc -version`)
- Dune version: (output of `dune --version`)
- OS: (Linux/macOS/Windows)
```

### Feature Requests

Create an issue with:

```
## Description
Brief summary of the feature.

## Motivation
Why is this needed?

## Proposed Implementation
How might this be implemented?

## Alternatives Considered
Other approaches?
```

## Documentation

Documentation is mandatory for:
- Public APIs (all .mli files)
- New modules
- Complex algorithms
- Security-critical code

Use ocamldoc format:

```ocaml
(** Explanation of the module.
    
    This module provides [functionality].
    
    {1 Examples}
    
    {[
      let x = Module.function arg in
      ...
    ]}
    
    {1 Limitations}
    
    - Only supports secp256k1
    - Does not handle ...
 *)
```

## Questions?

- Check existing docs: `docs/`, `README.md`, `MEGAPLAN.md`
- Open a discussion issue on GitHub
- Contact maintainers (see CONTRIBUTING.md footer)

---

Thank you for contributing to ecdsa-ocaml! 🙏
