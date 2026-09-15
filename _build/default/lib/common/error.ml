(* lib/common/error.ml
   Four error families, one per layer boundary.
   Every fallible function above this layer returns one of these. *)

module Parse_error = struct
  type t =
    | Bad_length    of string
    | Bad_prefix    of string
    | Bad_hex       of string
    | Truncated     of string
    | Trailing_data of string
    | Not_on_curve  of string
    | Non_canonical of string
  let to_string = function
    | Bad_length    c -> Printf.sprintf "%s: bad length" c
    | Bad_prefix    c -> Printf.sprintf "%s: bad prefix" c
    | Bad_hex       c -> Printf.sprintf "%s: bad hex" c
    | Truncated     c -> Printf.sprintf "%s: truncated" c
    | Trailing_data c -> Printf.sprintf "%s: trailing data" c
    | Not_on_curve  c -> Printf.sprintf "%s: point not on curve" c
    | Non_canonical c -> Printf.sprintf "%s: non-canonical encoding" c
end

module Der_error = struct
  type t =
    | Empty
    | Not_a_sequence
    | Bad_length
    | Not_an_integer
    | Negative_integer
    | Excessive_padding
    | Trailing_bytes
    | Missing_sighash_byte
    | R_out_of_range
    | S_out_of_range
    | High_s
  let to_string = function
    | Empty                -> "DER: empty"
    | Not_a_sequence       -> "DER: not a SEQUENCE"
    | Bad_length           -> "DER: bad length encoding"
    | Not_an_integer       -> "DER: not an INTEGER"
    | Negative_integer     -> "DER: negative INTEGER"
    | Excessive_padding    -> "DER: unnecessary 0x00 padding"
    | Trailing_bytes       -> "DER: trailing bytes"
    | Missing_sighash_byte -> "DER: missing sighash byte"
    | R_out_of_range       -> "DER: r outside [1, n-1]"
    | S_out_of_range       -> "DER: s outside [1, n-1]"
    | High_s               -> "DER: s > n/2 (BIP62 low-S violated)"
end

module Signature_error = struct
  type t =
    | Zero_r
    | Zero_s
    | Zero_nonce
    | Zero_private_key
    | Non_invertible of string
    | Verification_failed
    | Public_key_mismatch
  let to_string = function
    | Zero_r              -> "r is zero"
    | Zero_s              -> "s is zero"
    | Zero_nonce          -> "nonce is zero"
    | Zero_private_key    -> "private key is zero"
    | Non_invertible c    -> Printf.sprintf "%s is not invertible" c
    | Verification_failed -> "ECDSA verification failed"
    | Public_key_mismatch -> "recovered public key does not match"
end

module Recovery_error = struct
  type t =
    | Signature_error   of Signature_error.t
    | No_shared_r
    | Identical_signatures
    | Zero_denominator  of string
    | Recovered_k_is_zero
    | Recovered_d_is_zero
    | No_valid_recovery_id
  let to_string = function
    | Signature_error e    -> Signature_error.to_string e
    | No_shared_r          -> "signatures do not share r"
    | Identical_signatures -> "signatures are identical"
    | Zero_denominator c   -> Printf.sprintf "%s = 0" c
    | Recovered_k_is_zero  -> "recovered k is zero"
    | Recovered_d_is_zero  -> "recovered d is zero"
    | No_valid_recovery_id -> "no recovery id yielded a valid public key"
end
