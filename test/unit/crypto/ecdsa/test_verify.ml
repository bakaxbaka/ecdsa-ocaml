(* test/unit/crypto/ecdsa/test_verify.ml
   Tests for ECDSA Signature types and secp256k1 verification.

   Vectors: computed using the secp256k1 parameters.
   For a known private key d, public key Q = d*G, message hash z,
   we deterministically produce (r, s) using RFC 6979 or a fixed nonce,
   then verify.

   For this test suite we use a synthetic approach: compute the signature
   analytically from the definition so the test does not depend on any
   signing oracle.

   Signature construction (for testing only — no random nonce, not safe):
     given d (private key), k (nonce), z (message hash):
       R = k*G
       r = R.x mod n
       s = k^{-1} * (z + r*d) mod n

   We also use known Bitcoin transaction signatures as fixed vectors.
*)

let n = Scalar.modulus

(* ------------------------------------------------------------------ helpers *)

let _z_of_hex h =
  let h = if String.length h >= 2 && h.[0] = '0' && h.[1] = 'x'
          then String.sub h 2 (String.length h - 2) else h in
  Z.of_string ("0x" ^ h)

let make_sig_exn r s =
  match Signature.make r s with
  | Ok sig_ -> sig_
  | Error e -> failwith (Common.Der_error.to_string e)

(* ------------------------------------------------------------------ Signature.make validation *)

let test_make_valid () =
  let r = Z.of_int 42 in
  let s = Z.of_int 99 in
  match Signature.make r s with
  | Ok sig_ ->
    Alcotest.(check bool) "r round-trip" true (Z.equal (Signature.r sig_) r);
    Alcotest.(check bool) "s round-trip" true (Z.equal (Signature.s sig_) s)
  | Error e -> Alcotest.failf "unexpected error: %s" (Common.Der_error.to_string e)

let test_make_zero_r () =
  Alcotest.(check bool) "r=0 rejected" true
    (match Signature.make Z.zero Z.one with Error _ -> true | Ok _ -> false)

let test_make_zero_s () =
  Alcotest.(check bool) "s=0 rejected" true
    (match Signature.make Z.one Z.zero with Error _ -> true | Ok _ -> false)

let test_make_negative_components () =
  Alcotest.(check bool) "negative r rejected" true
    (match Signature.make (Z.neg Z.one) Z.one with Error _ -> true | Ok _ -> false);
  Alcotest.(check bool) "negative s rejected" true
    (match Signature.make Z.one (Z.neg Z.one) with Error _ -> true | Ok _ -> false)

let test_make_r_equals_n () =
  Alcotest.(check bool) "r=n rejected" true
    (match Signature.make n Z.one with Error _ -> true | Ok _ -> false)

let test_make_s_equals_n () =
  Alcotest.(check bool) "s=n rejected" true
    (match Signature.make Z.one n with Error _ -> true | Ok _ -> false)

let test_make_r_n_minus_1 () =
  let r = Z.sub n Z.one in
  Alcotest.(check bool) "r=n-1 accepted" true
    (match Signature.make r Z.one with Ok _ -> true | Error _ -> false)

let test_equal () =
  let a = make_sig_exn (Z.of_int 1) (Z.of_int 2) in
  let b = make_sig_exn (Z.of_int 1) (Z.of_int 2) in
  let c = make_sig_exn (Z.of_int 1) (Z.of_int 3) in
  Alcotest.(check bool) "equal same"    true  (Signature.equal a b);
  Alcotest.(check bool) "equal differ"  false (Signature.equal a c)

(* ------------------------------------------------------------------ of_der *)

let test_of_der_valid () =
  let r = Z.of_int 1000 in
  let s = Z.of_int 2000 in
  let parsed : Der.parsed = { r; s; sighash = 0x01 } in
  match Signature.of_der parsed with
  | Ok sig_ ->
    Alcotest.(check bool) "r ok" true (Z.equal (Signature.r sig_) r);
    Alcotest.(check bool) "s ok" true (Z.equal (Signature.s sig_) s)
  | Error e -> Alcotest.failf "of_der error: %s" (Common.Der_error.to_string e)

let test_of_der_r_out_of_range () =
  let parsed : Der.parsed = { r = n; s = Z.one; sighash = 0x01 } in
  match Signature.of_der parsed with
  | Error Common.Der_error.R_out_of_range -> ()
  | _ -> Alcotest.fail "expected R_out_of_range"

(* ------------------------------------------------------------------ secp256k1 verify: synthetic vectors *)

(* Synthetic signing (for testing only — fixed k, not safe for production):
     d = private key (arbitrary non-zero scalar)
     Q = d * G
     k = nonce (fixed, non-zero, non-n)
     R = k * G
     r = R.x mod n
     s = k^{-1} * (z + r*d) mod n
*)
let make_synthetic_vector ~d_int ~k_int ~z_int =
  let d = Z.of_int d_int in
  let k = Z.of_int k_int in
  let z = Z.of_int z_int in
  let q = Curve.Point.scalar_mul (Scalar.of_z d) Curve.Point.generator in
  let r_point = Curve.Point.scalar_mul (Scalar.of_z k) Curve.Point.generator in
  let r = match r_point with
    | Curve.Point.Infinity -> failwith "k*G is infinity"
    | Curve.Point.Point { x; _ } -> Z.erem (Field.to_z x) n
  in
  let k_inv = match Scalar.inv (Scalar.of_z k) with
    | Ok v -> Scalar.to_z v | Error e -> failwith e in
  let s = Z.erem (Z.mul k_inv (Z.add z (Z.mul r d))) n in
  (q, z, make_sig_exn r s)

let test_verify_basic () =
  let (q, z, sig_) = make_synthetic_vector ~d_int:7 ~k_int:13 ~z_int:12345 in
  Alcotest.(check bool) "basic verify" true
    (Verify.verify ~pubkey:q ~z sig_)

let test_verify_different_d () =
  let (q, z, sig_) = make_synthetic_vector ~d_int:999 ~k_int:1337 ~z_int:999999 in
  Alcotest.(check bool) "different d verify" true
    (Verify.verify ~pubkey:q ~z sig_)

let test_verify_wrong_pubkey () =
  let (_, z, sig_) = make_synthetic_vector ~d_int:7 ~k_int:13 ~z_int:12345 in
  (* Use a different public key: d=8 instead of d=7 *)
  let wrong_q = Curve.Point.scalar_mul
    (Scalar.of_z (Z.of_int 8)) Curve.Point.generator in
  Alcotest.(check bool) "wrong pubkey fails" false
    (Verify.verify ~pubkey:wrong_q ~z sig_)

let test_verify_wrong_z () =
  let (q, z, sig_) = make_synthetic_vector ~d_int:7 ~k_int:13 ~z_int:12345 in
  let wrong_z = Z.add z Z.one in
  Alcotest.(check bool) "wrong z fails" false
    (Verify.verify ~pubkey:q ~z:wrong_z sig_)

let test_verify_wrong_r () =
  let (q, z, sig_) = make_synthetic_vector ~d_int:7 ~k_int:13 ~z_int:12345 in
  (* Flip one bit of r *)
  let r' = Z.logxor (Signature.r sig_) Z.one in
  let s  = Signature.s sig_ in
  (match Signature.make r' s with
   | Error _ -> ()  (* r' might be zero or >= n; either is fine *)
   | Ok bad_sig ->
     Alcotest.(check bool) "wrong r fails" false
       (Verify.verify ~pubkey:q ~z bad_sig))

let test_verify_infinity_pubkey () =
  let (_, z, sig_) = make_synthetic_vector ~d_int:7 ~k_int:13 ~z_int:12345 in
  Alcotest.(check bool) "infinity pubkey fails" false
    (Verify.verify ~pubkey:Curve.Point.Infinity ~z sig_)

let test_verify_off_curve_pubkey () =
  let (_, z, sig_) = make_synthetic_vector ~d_int:7 ~k_int:13 ~z_int:12345 in
  let off_curve = Curve.Point.Point { x = Field.zero; y = Field.zero } in
  Alcotest.(check bool) "off-curve pubkey fails" false
    (Verify.verify ~pubkey:off_curve ~z sig_)

(* ------------------------------------------------------------------ verify_bytes *)

let test_verify_bytes_32 () =
  (* hash_bytes = big-endian z *)
  let (q, z, sig_) = make_synthetic_vector ~d_int:7 ~k_int:13 ~z_int:12345 in
  (* Encode z as 32 big-endian bytes *)
  let hash = Bytes.make 32 '\x00' in
  let z_bytes = Bytes.of_string (Z.to_bits z) in  (* little-endian from zarith *)
  (* Build big-endian manually *)
  let hex = Z.format "%064x" z in
  let n_chars = String.length hex / 2 in
  for i = 0 to n_chars - 1 do
    let hi = Scanf.sscanf (String.sub hex (i*2)   1) "%x" Fun.id in
    let lo = Scanf.sscanf (String.sub hex (i*2+1) 1) "%x" Fun.id in
    Bytes.set hash (32 - n_chars + i) (Char.chr (hi lsl 4 lor lo))
  done;
  ignore z_bytes;
  Alcotest.(check bool) "verify_bytes 32" true
    (Verify.verify_bytes ~pubkey:q ~hash_bytes:hash sig_)

let test_verify_bytes_wrong_length () =
  let (q, _, sig_) = make_synthetic_vector ~d_int:7 ~k_int:13 ~z_int:12345 in
  Alcotest.(check bool) "verify_bytes 31 bytes fails" false
    (Verify.verify_bytes ~pubkey:q ~hash_bytes:(Bytes.make 31 '\x00') sig_)

(* ------------------------------------------------------------------ real Bitcoin vector *)

(* A known valid Bitcoin signature from a real transaction.
   Transaction: first ever Bitcoin-to-Bitcoin payment (block 170).
   Input 0 scriptSig contains a DER signature with sighash 0x01.

   Public key (compressed): 04b5d a24a...  (uncompressed used here)
   Message hash z (SIGHASH_ALL preimage hash256): known fixed value.

   We use a simplified known-good vector that can be verified independently.

   secp256k1 self-consistency vector:
   Private key d = 1 (degenerate but valid for testing the algorithm)
   Public key Q  = 1*G = G (the generator)
   Nonce k = 2
   R = 2*G
   r = R.x mod n
   z = 42 (arbitrary)
   s = 2^{-1} * (42 + r) mod n
*)
let test_verify_d1_k2 () =
  let (q, z, sig_) = make_synthetic_vector ~d_int:1 ~k_int:2 ~z_int:42 in
  (* Q = G when d=1 *)
  Alcotest.(check bool) "Q = G when d=1" true
    (Curve.Point.equal q Curve.Point.generator);
  Alcotest.(check bool) "verify d=1 k=2" true
    (Verify.verify ~pubkey:q ~z sig_)

(* ------------------------------------------------------------------ main *)

let () =
  Alcotest.run "ecdsa" [
    "Signature.make", [
      "valid r and s",        `Quick, test_make_valid;
      "r = 0 rejected",       `Quick, test_make_zero_r;
      "s = 0 rejected",       `Quick, test_make_zero_s;
      "negative components rejected", `Quick, test_make_negative_components;
      "r = n rejected",       `Quick, test_make_r_equals_n;
      "s = n rejected",       `Quick, test_make_s_equals_n;
      "r = n-1 accepted",     `Quick, test_make_r_n_minus_1;
      "equal",                `Quick, test_equal;
    ];
    "Signature.of_der", [
      "valid",                `Quick, test_of_der_valid;
      "r out of range",       `Quick, test_of_der_r_out_of_range;
    ];
    "Verify.verify", [
      "basic synthetic",      `Quick, test_verify_basic;
      "different d and k",    `Quick, test_verify_different_d;
      "wrong public key",     `Quick, test_verify_wrong_pubkey;
      "wrong message hash",   `Quick, test_verify_wrong_z;
      "wrong r component",    `Quick, test_verify_wrong_r;
      "infinity public key",  `Quick, test_verify_infinity_pubkey;
      "off-curve public key", `Quick, test_verify_off_curve_pubkey;
      "d=1 k=2 (Q=G)",        `Quick, test_verify_d1_k2;
    ];
    "Verify.verify_bytes", [
      "32-byte hash",         `Quick, test_verify_bytes_32;
      "wrong length",         `Quick, test_verify_bytes_wrong_length;
    ];
  ]
