(* lib/crypto/scalar/scalar.ml
   Scalar arithmetic modulo the secp256k1 group order n.

   The module defines its operations once, inside [T], and then exposes them with
   [include T].  An earlier revision defined the whole API twice — once in [T] and
   again, byte for byte, at the top level after the [include].  Both copies
   compiled and agreed, so nothing misbehaved, but the duplication meant any
   future edit could land on one copy and silently do nothing.  That is exactly
   the class of defect this project's README says the rewrite exists to remove,
   so it is removed here rather than left as a hazard.

   The [.mli] wraps everything under [module T] and then includes it, matching
   [Field] and keeping the two crypto primitive modules symmetric. *)

module T = struct
  (** The secp256k1 group order n. *)
  let modulus =
    Z.of_string "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"

  (** Reduce any integer into the canonical range [0, n-1].

      Uses Euclidean remainder so the result is never negative, then folds a
      negative zero-result back into range. *)
  let of_z z =
    let r = Z.erem z modulus in
    if Z.sign r < 0 then Z.add r modulus else r

  (** Every value of type [t] is already a canonical representative, so this is
      the identity.  Present so callers never need to know that. *)
  let to_z (x : Z.t) : Z.t = x

  type t = Z.t

  let zero = Z.zero
  let one = Z.one

  let add x y = of_z Z.(x + y)
  let sub x y = of_z Z.(x - y)
  let mul x y = of_z Z.(x * y)

  let neg x = if Z.equal x Z.zero then Z.zero else Z.sub modulus x

  (** Modular inverse.  [Error] on zero, which has no inverse; every other
      residue is invertible because n is prime. *)
  let inv x =
    if Z.equal x Z.zero then Error "Cannot invert zero"
    else
      let i = Z.invert x modulus in
      if Z.equal i Z.zero then Error "Scalar is not invertible" else Ok (of_z i)

  (** Exponentiation.  A negative exponent inverts first, so the function is
      total over the integers rather than raising on a negative exponent. *)
  let pow x exponent =
    if Z.sign exponent < 0 then
      match inv x with
      | Error e -> failwith e
      | Ok x_inv -> Z.powm x_inv (Z.neg exponent) modulus
    else Z.powm x exponent modulus

  let equal = Z.equal
  let compare = Z.compare
  let is_zero x = Z.equal x Z.zero

  (** Zero-padded to 64 hex characters, which is 32 bytes: the wire width of a
      scalar in Bitcoin's serialisation. *)
  let to_hex x = Z.format "%064x" x

  (** Parses hex, with or without a leading [0x], and reduces modulo n. *)
  let of_hex s =
    try
      let s =
        if String.length s >= 2 && String.sub s 0 2 = "0x" then
          String.sub s 2 (String.length s - 2)
        else s
      in
      if s = "" then Error "Empty hexadecimal string"
      else Ok (of_z (Z.of_string ("0x" ^ s)))
    with _ -> Error "Invalid hexadecimal string"
end

include T
