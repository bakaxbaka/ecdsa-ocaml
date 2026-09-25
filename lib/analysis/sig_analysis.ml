(** Detection of reused ECDSA nonces on secp256k1. *)

type recovered_key = {
  private_key : Z.t;
  public_key : Curve.Point.t;
  first : Observation.t;
  second : Observation.t;
}

let modulus = Scalar.modulus

let modulo x =
  let r = Z.erem x modulus in
  if Z.sign r < 0 then Z.add r modulus else r

let inverse x =
  let x = modulo x in
  if Z.equal x Z.zero then None
  else
    let inv = Z.invert x modulus in
    if Z.equal inv Z.zero then None else Some inv

let recover_pair (first : Observation.t) (second : Observation.t) =
  if not (Z.equal first.r second.r) || Z.equal first.z second.z then None
  else
    match inverse (Z.sub first.s second.s) with
    | None -> None
    | Some denominator_inverse ->
      let nonce = modulo (Z.mul (Z.sub first.z second.z) denominator_inverse) in
      match inverse first.r with
      | None -> None
      | Some r_inverse ->
        let private_key =
          modulo (Z.mul (Z.sub (Z.mul first.s nonce) first.z) r_inverse)
        in
        if Z.equal private_key Z.zero then None
        else
          let public_key =
            Curve.Point.scalar_mul (Scalar.of_z private_key) Curve.Point.generator
          in
          if Curve.Point.equal public_key first.pubkey
             && Curve.Point.equal public_key second.pubkey
          then Some { private_key; public_key; first; second }
          else None

let recover_private_keys observations =
  let groups = Hashtbl.create (List.length observations) in
  List.iter (fun observation ->
      let prior = Option.value ~default:[] (Hashtbl.find_opt groups observation.r) in
      Hashtbl.replace groups observation.r (observation :: prior)) observations;
  let recovered = ref [] in
  Hashtbl.iter (fun _ group ->
      let rec compare_each = function
        | [] -> ()
        | observation :: rest ->
          List.iter (fun other ->
              match recover_pair observation other with
              | None -> ()
              | Some key -> recovered := key :: !recovered) rest;
          compare_each rest
      in
      compare_each group) groups;
  List.rev !recovered
