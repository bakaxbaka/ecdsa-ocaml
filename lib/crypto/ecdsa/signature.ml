(* lib/crypto/ecdsa/signature.ml
   ECDSA signature domain type for secp256k1. *)

(* secp256k1 group order n *)
let n = Scalar.modulus

type t = { r : Z.t; s : Z.t }

let make r s =
<<<<<<< HEAD
  if Z.compare r Z.zero < 0   then Error Common.Der_error.R_out_of_range
  else if Z.equal r Z.zero    then Error Common.Der_error.Bad_length
  else if Z.compare r n >= 0  then Error Common.Der_error.R_out_of_range
  else if Z.compare s Z.zero < 0   then Error Common.Der_error.S_out_of_range
  else if Z.equal s Z.zero    then Error Common.Der_error.Bad_length
=======
  if Z.sign r < 0          then Error Common.Der_error.Bad_length   (* negative r *)
  else if Z.equal r Z.zero         then Error Common.Der_error.Bad_length   (* zero r *)
  else if Z.compare r n >= 0  then Error Common.Der_error.R_out_of_range
  else if Z.sign s < 0          then Error Common.Der_error.Bad_length   (* negative s *)
  else if Z.equal s Z.zero    then Error Common.Der_error.Bad_length   (* zero s *)
>>>>>>> d919601fbeee4f3cd7a17a6c32768d0769687a7e
  else if Z.compare s n >= 0  then Error Common.Der_error.S_out_of_range
  else Ok { r; s }

let r t = t.r
let s t = t.s

let equal a b = Z.equal a.r b.r && Z.equal a.s b.s

let of_der (parsed : Der.parsed) = make parsed.r parsed.s
