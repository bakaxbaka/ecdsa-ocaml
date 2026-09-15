(* lib/crypto/ecdsa/verify.ml
   secp256k1 ECDSA verification.

   Algorithm (per SEC1 §4.1.4 and NIST FIPS 186):
     w  = s^{-1} mod n
     u1 = z * w  mod n
     u2 = r * w  mod n
     R  = u1*G + u2*Q
     valid iff R != Infinity and (R.x mod n) = r

   No Bitcoin-specific knowledge here. *)

let n = Scalar.modulus

(* Big-endian bytes -> Z.t *)
let z_of_bytes b =
  let len = Bytes.length b in
  let result = ref Z.zero in
  for i = 0 to len - 1 do
    result := Z.add
      (Z.shift_left !result 8)
      (Z.of_int (Char.code (Bytes.get b i)))
  done;
  !result

let verify ~pubkey ~z (sig_ : Signature.t) =
  (* Public key must not be the point at infinity and must be on the curve. *)
  match pubkey with
  | Curve.Point.Infinity -> false
<<<<<<< HEAD
  | _ ->
    (* Verify public key is on the curve before using it *)
    if not (Curve.Point.is_on_curve pubkey) then false
    else
=======
  | Curve.Point.Point _ ->
    if not (Curve.Point.is_on_curve pubkey) then false
    else begin
>>>>>>> d919601fbeee4f3cd7a17a6c32768d0769687a7e
      let r = Signature.r sig_ in
      let s = Signature.s sig_ in
      (* s must be invertible mod n (guaranteed by Signature.make, but be safe) *)
      match Scalar.inv (Scalar.of_z s) with
      | Error _ -> false
      | Ok w_scalar ->
        let w  = Scalar.to_z w_scalar in
        let u1 = Z.erem (Z.mul z  w) n in
        let u2 = Z.erem (Z.mul r  w) n in
        let g  = Curve.Point.generator in
        (* R = u1*G + u2*Q *)
        let point_u1g = Curve.Point.scalar_mul (Scalar.of_z u1) g       in
        let point_u2q = Curve.Point.scalar_mul (Scalar.of_z u2) pubkey  in
        let r_point   = Curve.Point.add point_u1g point_u2q in
        (* Reject point at infinity *)
        match r_point with
        | Curve.Point.Infinity -> false
        | Curve.Point.Point { x; _ } ->
          (* R.x mod n should equal r *)
          let rx_mod_n = Z.erem (Field.to_z x) n in
          Z.equal rx_mod_n r
<<<<<<< HEAD
=======
    end
>>>>>>> d919601fbeee4f3cd7a17a6c32768d0769687a7e

let verify_bytes ~pubkey ~hash_bytes sig_ =
  if Bytes.length hash_bytes <> 32 then false
  else verify ~pubkey ~z:(z_of_bytes hash_bytes) sig_
