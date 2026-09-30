(* test/unit/analysis/test_sig_analysis.ml
   Nonce-reuse recovery.

   Adapted to the merged analysis API. The original version of this test was
   written against a different analysis layer: it built [Observation.t] values via
   [Observation.make ~txid ~input_index ~r ~s ~z ~pubkey] and called
   [recover_private_keys] on those, expecting a [recovered_key] record. In the
   merged tree that module is gone; [Sig_analysis.recover_private_keys] takes
   [signature_record list] and returns the recovered key together with the pair of
   records it came from.

   The test's substance is unchanged and is the point of it: two signatures that
   share a nonce, produced from a known private key, must yield exactly that key
   back. Both signatures are built from the ECDSA relation itself
   (s = k^-1 (z + r*d) mod n, with r = x(k*G) mod n), so a regression in the
   recovery algebra makes the expected key fail to come back rather than making
   the test vacuous. *)

let modulus = Scalar.modulus
let modulo x = Z.erem x modulus

(* Build a signature_record for a known (private key d, nonce k, message hash z).
   r is the x-coordinate of k*G reduced mod n, and s follows from the signing
   equation, so the record is a genuine ECDSA signature rather than a fabricated
   pair of numbers. *)
let record ~tx_id ~z ~private_key ~nonce =
  let point = Curve.Point.scalar_mul (Scalar.of_z nonce) Curve.Point.generator in
  let r =
    match Curve.Point.x point with
    | Some x -> modulo (Field.to_z x)
    | None -> failwith "nonce produced the point at infinity"
  in
  let nonce_inv = Z.invert nonce modulus in
  let s = modulo (Z.mul nonce_inv (Z.add z (Z.mul r private_key))) in
  let pubkey =
    Curve.Point.to_compressed
      (Curve.Point.scalar_mul (Scalar.of_z private_key) Curve.Point.generator)
  in
  { Analysis_signature.Sig_analysis.tx_id;
    input_index = 0;
    pubkey = Some pubkey;
    r;
    s;
    z = Some z;
    timestamp = None }

let test_recover_reused_nonce () =
  let private_key = Z.of_int 42 and nonce = Z.of_int 17 in
  let first = record ~tx_id:"one" ~z:(Z.of_int 10) ~private_key ~nonce in
  let second = record ~tx_id:"two" ~z:(Z.of_int 20) ~private_key ~nonce in
  match Analysis_signature.Sig_analysis.recover_private_keys [ first; second ] with
  | [ (key, _, _) ] ->
    Alcotest.(check string) "recovered private key" "2a" (Z.format "%x" key)
  | [] -> Alcotest.fail "no private key was recovered from a reused nonce"
  | results ->
    Alcotest.failf "expected exactly one recovered key, got %d" (List.length results)

(* A nonce that differs between the two signatures must NOT yield a key. This
   guards the other direction: a recovery routine that always returns something
   would pass the test above while being useless. *)
let test_distinct_nonces_recover_nothing () =
  let private_key = Z.of_int 42 in
  let first = record ~tx_id:"one" ~z:(Z.of_int 10) ~private_key ~nonce:(Z.of_int 17) in
  let second = record ~tx_id:"two" ~z:(Z.of_int 20) ~private_key ~nonce:(Z.of_int 18) in
  match Analysis_signature.Sig_analysis.recover_private_keys [ first; second ] with
  | [] -> ()
  | _ -> Alcotest.fail "distinct nonces must not yield a key"

(* Two signatures over the SAME message are duplicates, not reuse, and must not
   yield a key: k = (z1 - z2)/(s1 - s2) divides by zero there. *)
let test_same_message_recovers_nothing () =
  let private_key = Z.of_int 42 and nonce = Z.of_int 17 in
  let first = record ~tx_id:"one" ~z:(Z.of_int 10) ~private_key ~nonce in
  let second = record ~tx_id:"two" ~z:(Z.of_int 10) ~private_key ~nonce in
  match Analysis_signature.Sig_analysis.recover_private_keys [ first; second ] with
  | [] -> ()
  | _ -> Alcotest.fail "identical message hashes must not yield a key"

let () =
  Alcotest.run "signature analysis" [
    "nonce reuse", [
      Alcotest.test_case "recovers the key" `Quick test_recover_reused_nonce;
      Alcotest.test_case "distinct nonces recover nothing" `Quick test_distinct_nonces_recover_nothing;
      Alcotest.test_case "same message recovers nothing" `Quick test_same_message_recovers_nothing;
    ];
  ]
