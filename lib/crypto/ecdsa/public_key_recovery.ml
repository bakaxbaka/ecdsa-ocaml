(* lib/crypto/ecdsa/public_key_recovery.ml
   ECDSA public key recovery from signature and message hash.

   Algorithm (per SEC1 §4.1.6):
   Given (r, s, z) and recovery_id:
     1. Compute R = (r, y) where y is derived from recovery_id
     2. Check R is on curve and R != Infinity
     3. Compute r_inv = r^{-1} mod n
     4. Compute Q = r_inv * (s*R - z*G)
     5. Return Q

   The recovery_id encodes which of the two possible y-coordinates for R to use
   (even/odd for compressed format) plus a hint for the high-s form.

   Reference: https://github.com/bitcoin/bips/blob/master/bip-0137.mediawiki
*)

let n = Scalar.modulus

(* Compute y coordinate from r and recovery_id parity *)
let compute_y_from_r ~curve_point_r ~recovery_id =
  let parity = recovery_id land 0x01 in
  let y = Curve.Point.y curve_point_r in
  match y with
  | None -> None
  | Some y_val ->
    let current_parity = Z.testbit (Field.to_z y_val) 0 in
    if current_parity = (parity = 1) then
      Some curve_point_r
    else
      (* Flip y coordinate *)
      Some (Curve.Point.neg curve_point_r)

(* Try to reconstruct point R from r value and recovery_id parity *)
let reconstruct_r (r : Scalar.t) (recovery_id : int) =
  (* For secp256k1, we need to solve y^2 = x^3 + 7 for y given x = r *)
  let x = Field.of_z (Scalar.to_z r) in
  (* Compute alpha = x^3 + 7 *)
  let alpha = Field.add (Field.mul x (Field.mul x x)) (Field.of_z (Z.of_int 7)) in
  (* Compute sqrt_mod_p(alpha) *)
  let sqrt_exp = Z.div (Z.add Field.modulus Z.one) (Z.of_int 4) in
  let y_attempt = Field.pow alpha sqrt_exp in
  (* Check if y_attempt^2 = alpha *)
  if not (Field.equal (Field.mul y_attempt y_attempt) alpha) then
    None
  else begin
    (* Try both y and -y to find the right one based on recovery_id parity *)
    let parity = recovery_id land 0x01 in
    let y_even = y_attempt in
    let y_odd = Field.neg y_attempt in
    let y_val = if Z.testbit (Field.to_z y_even) 0 = (parity = 1) then y_even else y_odd in
    Some (Curve.Point.Point { x; y = y_val })
  end

(* Recover public key candidates from signature and message hash *)
let recover_candidates ~z ~r ~s ~recovery_id : Curve.Point.t list =
  (* Recovery ID must be 0, 1, 2, or 3 *)
  if recovery_id < 0 || recovery_id > 3 then []
  else begin
    (* Try to reconstruct R from r and recovery_id parity *)
    match reconstruct_r (Scalar.of_z r) recovery_id with
    | None -> []
    | Some r_point ->
      (* Check R is on curve *)
      if not (Curve.Point.is_on_curve r_point) then []
      else
        let r_scalar = Scalar.of_z r in
        (* Compute r_inv = r^{-1} mod n *)
        match Scalar.inv r_scalar with
        | Error _ -> []
        | Ok r_inv ->
          let s_scalar = Scalar.of_z s in
          (* Compute Q = r_inv * (s*R - z*G) *)
          let sR = Curve.Point.scalar_mul s_scalar r_point in
          let zG = Curve.Point.scalar_mul (Scalar.of_z z) Curve.Point.generator in
          let sR_minus_zG = Curve.Point.add sR (Curve.Point.neg zG) in
          let q = Curve.Point.scalar_mul r_inv sR_minus_zG in
          (* Return Q if it's a valid point *)
          if Curve.Point.is_on_curve q then [q] else []
  end

(* Public key recovery from full signature *)
let recover_from_signature ~z (sig_ : Signature.t) (recovery_id : int) : Curve.Point.t list =
  recover_candidates ~z ~r:(Scalar.to_z (Signature.r sig_)) ~s:(Scalar.to_z (Signature.s sig_)) ~recovery_id

(* Verify recovered public key matches expected *)
let verify_recovered_key ~z (sig_ : Signature.t) (recovery_id : int) (expected_key : Curve.Point.t) : bool =
  let candidates = recover_from_signature ~z sig_ recovery_id in
  List.exists (Curve.Point.equal expected_key) candidates

(* Get all 4 possible public keys (recovery_id 0-3) *)
let recover_all_candidates ~z ~r ~s : Curve.Point.t list =
  let rec loop acc id =
    if id > 3 then List.rev acc
    else
      let candidates = recover_candidates ~z ~r ~s ~recovery_id:id in
      loop (candidates @ acc) (id + 1)
  in
  loop [] 0

(* Get all 4 possible public keys from full signature *)
let recover_all_from_signature ~z (sig_ : Signature.t) : Curve.Point.t list =
  recover_all_candidates ~z ~r:(Scalar.to_z (Signature.r sig_)) ~s:(Scalar.to_z (Signature.s sig_))
