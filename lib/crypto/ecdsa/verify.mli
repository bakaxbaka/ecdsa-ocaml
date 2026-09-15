(** secp256k1 ECDSA signature verification.

    Implements the standard ECDSA verification algorithm over secp256k1.
    No Bitcoin-specific concepts (transactions, scripts, SIGHASH) are present
    here; those belong in the layers above.

    {1 Algorithm}

    Given message hash z, signature (r, s), and public key Q:
    {v
      1. Compute w  = s^{-1} mod n
      2. Compute u1 = z * w  mod n
      3. Compute u2 = r * w  mod n
      4. Compute R  = u1*G + u2*Q
      5. Verify R != Infinity and R.x mod n = r
    v}

    {1 Inputs}

    - [pubkey]: a finite secp256k1 curve point
    - [z]: the message hash as a [Z.t], typically the 256-bit hash256 of a
      SIGHASH preimage, interpreted as a big-endian integer
    - [sig]: a validated {!Signature.t} with r, s in [1, n-1]
*)

(** [verify ~pubkey ~z sig] returns [true] if the signature is valid. *)
val verify : pubkey:Curve.Point.t -> z:Z.t -> Signature.t -> bool

(** [verify_bytes ~pubkey ~hash_bytes sig] interprets [hash_bytes] as a
    big-endian integer and calls {!verify}.  [hash_bytes] must be 32 bytes;
    returns [false] for any other length. *)
val verify_bytes : pubkey:Curve.Point.t -> hash_bytes:bytes -> Signature.t -> bool
