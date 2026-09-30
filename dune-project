(lang dune 3.0)
(name ecdsa_ocaml)
(version 0.1.0-alpha.1)
(package
 (name ecdsa_ocaml)
 (allow_empty)
 (synopsis "Typed ECDSA signature analysis for Bitcoin")
 (description "A security-focused OCaml implementation of secp256k1 ECDSA signature operations, Bitcoin transaction parsing, and reproducible cryptographic analysis.")
 (homepage "https://github.com/your-org/ecdsa-ocaml")
 (bug_reports "https://github.com/your-org/ecdsa-ocaml/issues")
 (documentation "https://your-org.github.io/ecdsa-ocaml")
 (license "MIT")
 (authors "Your Name <your.email@example.com>")
 (maintainers "Your Name <your.email@example.com>")
 (depends
  (ocaml (>= 4.14))
  (dune (>= 3.0))
  zarith
  digestif
  (alcotest :with-test)
  (qcheck :with-test)
  yojson))
