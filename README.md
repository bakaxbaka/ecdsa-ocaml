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
                         SIGNATURE ANALYSIS PIPELINE
================================================================================

`tools/dump_rsz.exe RAWTX_DIR rsz_database.csv` indexes the `*.hex` files in
`RAWTX_DIR`, then emits one CSV row per structurally valid DER signature.  The
input files must be named `<display-txid>.hex`; this lets the tool resolve
prevouts that are present in the same directory.  Its final `ecdsa_valid`
column is the quality gate: only rows whose value is `true` have a computed
signature hash verified against their extracted public key.

The extractor supports P2PKH, P2SH, P2PK, native P2WPKH/P2WSH, and nested
P2SH-P2WPKH/P2WSH where the parent transaction is available.  Rows that cannot
resolve a prevout or script code remain in the output with an empty `z_hex` and
a diagnostic `note`; they are not candidates for analysis.

Run nonce-reuse recovery only on that verified output:

    dune exec tools/recover_reused.exe -- rsz_database.csv

Every reported key is independently checked by deriving `d * G` and comparing
it to the public keys attached to both observations.  For a distributional
check of `r` bits (never `s`, which may be low-S normalised), use:

    octave --quiet --eval "addpath('tools/octave'); bit_bias('rsz_database.csv')"
