(** ECDSA signature domain types for secp256k1.

    A signature is a pair (r, s) of scalars in the range [1, n-1] where n is
    the secp256k1 group order.  This module provides a validated wrapper that
    refuses to construct a signature with out-of-range components.

    No Bitcoin-specific concepts (DER encoding, sighash types, scripts) belong
    here.  See {!Der} for DER parsing and {!Verify} for verification. *)

(** S-form classification: signatures with s <= n/2 are in low-S form,
    which is preferred in Bitcoin for malleability prevention. *)
type s_form = Low_s | High_s

(** A validated ECDSA signature: r and s are both in [1, n-1],
    with s_form tracking whether the s-component is in low or high form. *)
type t

(** [make r s] constructs a signature if both [r] and [s] are in [1, n-1].
    Returns [Error] if r <= 0, s <= 0, r >= n, or s >= n. *)
val make : Z.t -> Z.t -> (t, string) result

(** [r sig] returns the r component. *)
val r : t -> Scalar.t

(** [s sig] returns the s component. *)
val s : t -> Scalar.t

(** [s_form sig] returns the s-form classification. *)
val s_form : t -> s_form

(** [normalize_s sig] returns a copy of [sig] with s normalized to low-S form.
    Preserves the original signature's r and s_form for observation purposes. *)
val normalize_s : t -> (t, string) result

(** [equal a b] is structural equality: r_a = r_b, s_a = s_b, and s_form_a = s_form_b. *)
val equal : t -> t -> bool

(** [of_der parsed] converts a {!Der.parsed} value into a validated
    signature, additionally checking that r and s are in [1, n-1].
    Returns the same error type as {!make}. *)
val of_der : Der.parsed -> (t, string) result
