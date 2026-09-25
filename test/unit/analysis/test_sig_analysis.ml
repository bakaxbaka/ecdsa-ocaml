let modulus = Scalar.modulus
let modulo n = Z.erem n modulus

let observation ~txid ~z ~private_key ~nonce =
  let point = Curve.Point.scalar_mul (Scalar.of_z nonce) Curve.Point.generator in
  let r = match Curve.Point.x point with Some x -> modulo (Field.to_z x) | None -> assert false in
  let nonce_inv = Z.invert nonce modulus in
  let s = modulo (Z.mul nonce_inv (Z.add z (Z.mul r private_key))) in
  let pubkey = Curve.Point.scalar_mul (Scalar.of_z private_key) Curve.Point.generator in
  Observation.make ~txid ~input_index:0 ~r ~s ~z ~pubkey

let test_recover_reused_nonce () =
  let private_key = Z.of_int 42 and nonce = Z.of_int 17 in
  let first = observation ~txid:"one" ~z:(Z.of_int 10) ~private_key ~nonce in
  let second = observation ~txid:"two" ~z:(Z.of_int 20) ~private_key ~nonce in
  match Sig_analysis.recover_private_keys [first; second] with
  | [recovered] -> Alcotest.(check string) "private key" "2a" (Z.format "%x" recovered.private_key)
  | _ -> Alcotest.fail "expected exactly one recovered private key"

let () = Alcotest.run "signature analysis" ["nonce reuse", [Alcotest.test_case "recovers key" `Quick test_recover_reused_nonce]]
