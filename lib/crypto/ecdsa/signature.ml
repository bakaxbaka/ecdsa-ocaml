(* lib/crypto/ecdsa/signature.ml
   ECDSA signature domain type for secp256k1. *)

(* secp256k1 group order n — kept for potential external callers *)
let _n = Scalar.modulus

(* S-form classification: Low_s (s <= n/2) or High_s (s > n/2) *)
type s_form = Low_s | High_s

type t = { r : Scalar.t; s : Scalar.t; s_form : s_form }

(* Compute n/2 for secp256k1: (n-1)/2 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0 *)
let n_half_z =
  Z.of_string "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0"

let n_half = Scalar.of_z n_half_z

(* Determine s_form based on whether s <= n/2 *)
let classify_s_form s =
  if Scalar.compare s n_half <= 0 then Low_s else High_s

(* Make signature with strict validation: r != 0, s != 0, r < n, s < n, sign(r) > 0, sign(s) > 0 *)
let make r s =
  (* Convert to canonical scalars *)
  let r' = Scalar.of_z r in
  let s' = Scalar.of_z s in
  (* Validate: must be positive and less than n *)
  if Z.compare r Z.zero <= 0 then Error "r must be positive"
  else if Z.compare r Scalar.modulus >= 0 then Error "r must be less than n"
  else if Z.compare s Z.zero <= 0 then Error "s must be positive"
  else if Z.compare s Scalar.modulus >= 0 then Error "s must be less than n"
  else
    let s_form = classify_s_form s' in
    Ok { r = r'; s = s'; s_form }

(* Accessors *)
let r t = t.r
let s t = t.s
let s_form t = t.s_form

(* Normalize s to low-s form: returns { r; s' = min(s, n-s) } wrapped in Ok *)
let normalize_s sigm =
  let s_z = Scalar.to_z sigm.s in
  let n_z = Scalar.modulus in
  let s' = if Scalar.compare sigm.s n_half <= 0 then sigm.s else Scalar.of_z (Z.sub n_z s_z) in
  let s_form' = if Scalar.compare s' n_half <= 0 then Low_s else High_s in
  Ok { sigm with s = s'; s_form = s_form' }

(* with_s_form: set a specific s_form on a signature — used by callers that
   track original vs normalised form *)
let with_s_form sigm s_form =
  { sigm with s_form }
let _ = with_s_form

let equal a b =
  Scalar.equal a.r b.r && Scalar.equal a.s b.s && a.s_form = b.s_form

let of_der (parsed : Der.parsed) = make parsed.r parsed.s
