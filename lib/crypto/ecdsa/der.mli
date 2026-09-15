(** Strict Bitcoin DER signature parser.

    Parses a Bitcoin DER-encoded ECDSA signature with an appended sighash-type
    byte into its (r, s) integer components.

    {1 Bitcoin DER wire format}

    {v
      30               SEQUENCE tag
      <len>            total length of what follows (1 byte, ≤ 70)
      02               INTEGER tag for r
      <r_len>          length of r (1..33)
      <r bytes>        big-endian, unsigned, no unnecessary leading zeros
      02               INTEGER tag for s
      <s_len>          length of s (1..33)
      <s bytes>        big-endian, unsigned, no unnecessary leading zeros
      <sighash_byte>   0x01 | 0x02 | 0x03 | 0x81 | 0x82 | 0x83
    v}

    This parser is {e strict}: it enforces every rule that Bitcoin Core
    checks when validating a signature.  In particular it rejects:

    - Empty input
    - Wrong SEQUENCE tag (not 0x30)
    - SEQUENCE length inconsistent with the actual buffer
    - Wrong INTEGER tag (not 0x02) for r or s
    - Zero-length r or s
    - r or s value greater than 33 bytes
    - High bit set on first byte without a leading 0x00 padding byte
      (i.e., a value that would be interpreted as negative in DER)
    - Unnecessary leading 0x00 bytes (non-minimal encoding)
    - r or s whose decoded value is zero
    - Missing sighash byte

    It does {e not} check:
    - Whether r or s is within [1, n-1] for the secp256k1 order n
      (that check requires the scalar modulus and belongs in the ECDSA layer)
    - BIP62 low-S (also belongs in the ECDSA layer, not the wire parser)
*)

(** The result of a successful parse: r, s as arbitrary-precision integers,
    and the raw sighash-type byte. *)
type parsed = {
  r        : Z.t;
  s        : Z.t;
  sighash  : int;  (** Raw sighash byte, e.g. 0x01 for SIGHASH_ALL. *)
}

(** [of_bytes buf] parses [buf] as a Bitcoin DER signature with sighash byte.
    Returns [Error] for any structural or encoding violation. *)
val of_bytes : bytes -> (parsed, Common.Der_error.t) result

(** [of_hex h] decodes [h] from hex then calls {!of_bytes}.
    Accepts an optional leading "0x" prefix. *)
val of_hex : string -> (parsed, Common.Der_error.t) result
