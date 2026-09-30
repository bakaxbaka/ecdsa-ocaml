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

    Layer                                State         Tests
    ---------------------------------    -----------   -------
    common/   error families             builds clean     -
    crypto/   field, scalar, curve       complete           -
    crypto/   secp256k1 arithmetic       complete           -
    crypto/   ECDSA signature types      complete         18
    crypto/   ECDSA verification         complete         18
    crypto/   strict DER parser          complete         22
    crypto/   SHA-256 / hash256          complete         15
    bitcoin/  transaction parser         complete         24
    bitcoin/  script types               complete         24
    bitcoin/  script parser              complete         25
    bitcoin/  legacy SIGHASH             complete         19
    bitcoin/  BIP143 (SegWit) SIGHASH    complete         15
    bitcoin/  signature extraction       complete         13
    analysis/ nonce detection            skeleton           -
    storage/  persistence                skeleton           -
    application/ pipeline, CLI           skeleton           -

    CI                                   none yet
    CLI                                  none yet
    git history                          minimal

================================================================================
                                BUILD
================================================================================

  Requires opam, OCaml 4.14 or later, and Dune.

  Install dependencies:

    opam install -y dune zarith digestif alcotest qcheck yojson

  Build the whole project:

    opam exec -- dune build

  Zero output means success. Dune prints nothing on a clean build.

  Run tests:

    opam exec -- dune runtest

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
                         ENGINEERING REFERENCES
================================================================================

  The implementation and analysis work follows these primary references:

    ECDSA deterministic nonces
      RFC 6979
      https://datatracker.ietf.org/doc/html/rfc6979

    Elliptic-curve encoding and validation
      SEC 1: Elliptic Curve Cryptography
      https://www.secg.org/sec1-v2.pdf

    Bitcoin transaction and script serialization
      Bitcoin Developer Reference: Transactions
      https://developer.bitcoin.org/reference/transactions.html

    Dune builds, tests, documentation, and CI
      https://dune.readthedocs.io/en/stable/overview.html
      https://dune.readthedocs.io/en/stable/tests.html

    OCaml interface-first compilation model
      OCaml compiler manual, batch compilation
      https://ocaml.org/manual/5.2/comp.html

  Relevant OCaml implementation patterns include:

    - typed curve witnesses and explicit key/signature validation, as shown by
      vbmithr/ocaml-uecc's secp256k1 interface;
    - pure, narrow analysis APIs with recoverable errors represented by Result;
    - Alcotest and QCheck for deterministic examples, parser properties, and
      round-trip tests;
    - Dune libraries that preserve the dependency direction:
      common -> crypto -> bitcoin -> analysis -> storage -> application.

  These references constrain the next milestones: implement analysis against
  the existing typed primitives, test transaction-derived claims from source
  vectors, and do not promote dataset-level findings to library-level
  guarantees.
