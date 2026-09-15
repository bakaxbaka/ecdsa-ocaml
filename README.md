================================================================================
                              ecdsa-ocaml
================================================================================

  A typed OCaml implementation of ECDSA signature analysis and private key
  recovery on secp256k1, targeting Bitcoin transaction data.

  Rewritten from a Python prototype that was correct in intent but unsafe
  in practice: untyped integers everywhere, `except: pass` swallowing
  failures, and `confidence = 1.0` standing in for verification.

  The math is unchanged. The guarantees around it are new.

================================================================================
                                STATUS
================================================================================

  Honest. Not aspirational.

    Layer                                State
    ---------------------------------    --------------------------------------
    common/   error families             builds clean
    crypto/   field, scalar, curve       mid-refactor into curve/ sub-library
    bitcoin/  tx, sighash, addresses     not started (skeleton only)
    analysis/ nonce detection, recovery  not started
    storage/  persistence                not started
    application/ pipeline, CLI           not started

    Tests                                none yet
    CI                                   none yet
    CLI                                  none yet
    git history                          none yet

  The next deliverable is test/unit/crypto_curve/test_curve.ml -- eleven
  test cases proving the curve arithmetic is correct.

================================================================================
                                 WHY
================================================================================

  The Python prototype recovered private keys by finding repeated ECDSA
  nonces in Bitcoin transactions. It worked. It also:

    - Represented r, s, z, k, d as bare Python int, so nothing prevented
      adding a curve coordinate to a scalar.
    - Used `except: return None` at every fallible point, so failures were
      indistinguishable from "no result".
    - Reported `confidence = 1.0` when six algebraically equivalent
      formulas agreed -- which proves nothing, because they always agree
      if the input is valid.
    - Skipped SegWit inputs entirely (`if script_len == 0: continue`).
    - Verified recovery by string-comparing derived public keys, not by
      checking `address(d) == input_address`.

  This project fixes all five.

================================================================================
                              ARCHITECTURE
================================================================================

  Six layers. Each is a separate Dune library. A layer may depend only on
  layers below it. Dune enforces this via each layer's (libraries ...) clause.

                            application
                                 |
                            storage
                                 |
                            analysis
                                 |
                            bitcoin
                                 |
                            crypto
                                 |
                            common

  Rule: if you need a symbol from a layer ABOVE, the design is wrong.
  Move the symbol down.

================================================================================
                                BUILD
================================================================================

  Requires opam, OCaml 4.14 or later, and Dune.

  Install dependencies:

    opam install -y dune zarith digestif alcotest qcheck yojson

  Build the whole project:

    opam exec -- dune build

  Zero output means success. Dune prints nothing on a clean build.

  Per layer:

    opam exec -- dune build lib\common\
    opam exec -- dune build lib\crypto\
    opam exec -- dune build lib\crypto\curve\

  Run tests (once they exist):

    opam exec -- dune runtest

================================================================================
                                LAYOUT
================================================================================

  lib/
  |
  +-- dune                        (dirs common crypto bitcoin analysis storage application)
  |
  +-- common/
  |   +-- dune
  |   +-- common.ml               (re-exports of the four error families)
  |   +-- error.ml                (Parse_error, Der_error, Signature_error, Recovery_error)
  |
  +-- crypto/
  |   +-- dune                    (library crypto)
  |   +-- field.ml(i)             (F_p arithmetic, p = 2^256 - 2^32 - 977)
  |   +-- scalar.ml(i)            (F_n arithmetic, n = secp256k1 group order)
  |   |
  |   +-- curve/
  |       +-- dune                (library crypto_curve)
  |       +-- point.ml(i)         (type t = Infinity | Finite { x; y })
  |       +-- secp256k1.ml(i)     (a, b, generator, is_on_curve)
  |       +-- arithmetic.ml(i)    (neg, add, double, scalar_mul, equal)
  |       +-- serialization.ml(i) (SEC1 compressed / uncompressed)
  |
  +-- bitcoin/                    (not yet populated)
  +-- analysis/                   (not yet populated)
  +-- storage/                    (not yet populated)
  +-- application/                (not yet populated)

  test/
  +-- unit/
  |   +-- crypto_curve/
  |       +-- test_curve.ml       (next deliverable)
  +-- fixtures/                   (empty -- GEC 2 vectors go here)
