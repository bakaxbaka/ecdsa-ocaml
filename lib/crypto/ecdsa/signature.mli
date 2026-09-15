(** ECDSA signature domain types for secp256k1.

    A signature is a pair (r, s) of scalars in the range [1, n-1] where n is
    the secp256k1 group order.  This module provides a validated wrapper that
    refuses to construct a signature with out-of-range components.

    No Bitcoin-specific concepts (DER encoding, sighash types, scripts) belong
    here.  See {!Der} for DER parsing and {!Verify} for verification. *)

(** A validated ECDSA signature: r and s are both in [1, n-1]. *)
type t

(** [make r s] constructs a signature if both [r] and [s] are in [1, n-1].
    Returns an error if either component is not in [1, n-1], including
    negative or zero values. *)
val make : Z.t -> Z.t -> (t, Common.Der_error.t) result

(** [r sig] returns the r component. *)
val r : t -> Z.t

(** [s sig] returns the s component. *)
val s : t -> Z.t

(** [equal a b] is structural equality: r_a = r_b and s_a = s_b. *)
val equal : t -> t -> bool

(** [of_der parsed] converts a {!Der.parsed} value into a validated
    signature, additionally checking that r and s are in [1, n-1].
    Returns the same error type as {!make}. *)
val of_der : Der.parsed -> (t, Common.Der_error.t) result
