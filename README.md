A typed OCaml implementation of ECDSA signature analysis and private key recovery on secp256k1, targeting Bitcoin transaction data. Recovered from a Python prototype that was correct in intent but unsafe in practice: untyped integers everywhere, except: pass swallowing failures, and confidence = 1.0 standing in for verification.

This is a from-scratch rewrite with type-level separation of scalars, field elements, and curve points, plus explicit error types at every layer boundary.

Status
Honest. Not aspirational.

Layer	State
common/ — error families	Builds clean.
crypto/ — field, scalar, curve	Mid-refactor into curve/ sub-library. See Conventions.
bitcoin/ — tx parsing, sighash, addresses	Not started. Skeleton only.
analysis/ — nonce detection, recovery	Not started.
storage/ — persistence	Not started.
application/ — pipeline, CLI	Not started.
Tests	None yet. First test (test_curve.ml) is the next deliverable.
No commit history yet. No CI. No CLI.

Why this exists
The Python prototype recovered private keys by finding repeated ECDSA nonces in Bitcoin transactions. It worked. It also:

Represented r, s, z, k, and d as bare Python int, so nothing prevented adding a curve coordinate to a scalar

Used except: return None at every fallible point, so failures were indistinguishable from "no result"

Reported confidence = 1.0 when six algebraically equivalent formulas agreed — which proves nothing, because they always agree if the input is valid

Skipped SegWit inputs entirely (if script_len == 0: continue)

Verified recovery by string-comparing derived public keys, not by checking address(d) == input_address

This project fixes all five. The math is unchanged; the guarantees around it are new.

Architecture
Six layers. Each is a separate Dune library. A layer may depend only on layers below it. Dune enforces this via each layer's (libraries ...) clause.

text
application   (CLI, pipeline, orchestration)
     │
storage       (SQLite backend, in-memory backend, JSON export)
     │
analysis      (nonce detection, recovery formulas, evidence records)
     │
bitcoin       (transaction parsing, sighash, addresses, WIF)
     │
crypto        (field, scalar, curve, ECDSA, DER, hashing)
     │
common        (error families — the only shared vocabulary)
Rule: if you find yourself needing a symbol from a layer above, the design is wrong. Move the symbol down.

Build
Requires opam, OCaml 4.14 or later, and Dune.

powershell
opam install -y dune zarith digestif alcotest qcheck yojson
powershell
opam exec -- dune build
Zero output means success. Dune prints nothing on a clean build.

Per-layer:

powershell
opam exec -- dune build lib\common\
opam exec -- dune build lib\crypto\
opam exec -- dune build lib\crypto\curve\
Tests (once they exist):

powershell
opam exec -- dune runtest
Layout
text
lib/
├── dune                    (dirs common crypto bitcoin analysis storage application)
│
├── common/
│   ├── dune
│   ├── common.ml           (re-exports of the four error families)
│   └── error.ml            (Parse_error, Der_error, Signature_error, Recovery_error)
│
├── crypto/
│   ├── dune                (library crypto)
│   ├── field.ml(i)         (F_p arithmetic, p = 2²⁵⁶ − 2³² − 977)
│   ├── scalar.ml(i)        (F_n arithmetic, n = secp256k1 group order)
│   └── curve/
│       ├── dune            (library crypto_curve)
│       ├── point.ml(i)     (type t = Infinity | Finite { x; y })
│       ├── secp256k1.ml(i) (a, b, generator, is_on_curve)
│       ├── arithmetic.ml(i)(neg, add, double, scalar_mul, equal)
│       └── serialization.ml(i) (SEC1 compressed/uncompressed)
│
├── bitcoin/                (not yet populated)
├── analysis/               (not yet populated)
├── storage/                (not yet populated)
└── application/            (not yet populated)

test/
├── unit/
│   └── crypto_curve/
│       └── test_curve.ml   (next deliverable)
└── fixtures/               (empty — GEC 2 vectors go here)
