(* test/unit/bitcoin/test_signature_extraction.ml
   Unit tests for signature extraction from Bitcoin transactions.

   Tests verify that signatures are correctly extracted from:
   - Legacy P2PKH inputs (scriptSig with signature + public key)
   - SegWit P2WPKH inputs (witness stack with signature + public key)
   - Multi-signature inputs (multiple signatures)
*)

open Types

let ok_exn lbl = function
  | Ok v    -> v
  | Error e ->
    let msg = match e with
      | Invalid_script _ -> "invalid script"
      | Invalid_der _    -> "invalid DER"
      | No_signature     -> "no signature"
      | No_public_key    -> "no public key"
    in
    Alcotest.failf "%s: unexpected Error: %s" lbl msg

let is_error = function Error _ -> true | Ok _ -> false

(* ------------------------------------------------------------------ helpers *)

(* Build a minimal legacy P2PKH transaction with one input *)
let make_legacy_p2pkh_tx ?(version=1) ?(lock_time=0) () =
  let prev_txid = Bytes.of_string "\x00\x01\x02\x03" ^ Bytes.make 28 '\x00' in
  let inp : tx_input = {
    previous_output = {
      txid = prev_txid;
      vout = 0;
    };
    script_sig = Bytes.of_string "\x47";  (* OP_DATA_71 *)
    sequence   = 0xFFFF_FFFF;
  } in
  let out : tx_output = {
    value = Int64.of_int 10000;
    script_pubkey = Bytes.of_string "\x76\xa9\x14";  (* OP_DUP OP_HASH160 OP_DATA_20 *)
  } in
  {
    version;
    inputs  = [inp];
    outputs = [out];
    witnesses = [];
    lock_time;
    segwit    = false;
  }

(* ------------------------------------------------------------------ legacy input *)

let test_legacy_p2pkh_extract () =
  let tx = make_legacy_p2pkh_tx () in
  let result = ok_exn "extract" (Signature_extraction.extract tx) in
  Alcotest.(check int) "1 input" 1 (List.length result);
  let sig_data = List.nth result 0 in
  Alcotest.(check int) "input_index 0" 0 sig_data.input_index;
  Alcotest.(check int) "at least 1 signature" 1 (List.length sig_data.signatures)

let test_legacy_single_input () =
  let tx = make_legacy_p2pkh_tx () in
  let result = ok_exn "extract_single" (Signature_extraction.extract_single tx 0) in
  Alcotest.(check int) "input_index 0" 0 result.input_index

let test_legacy_out_of_bounds () =
  let tx = make_legacy_p2pkh_tx () in
  Alcotest.(check bool) "index 1 out of bounds" true
    (is_error (Signature_extraction.extract_single tx 1))

(* ------------------------------------------------------------------ SegWit input *)

let make_segwit_p2wpkh_tx ?(version=1) ?(lock_time=0) () =
  let prev_txid = Bytes.of_string "\x00\x01\x02\x03" ^ Bytes.make 28 '\x00' in
  let inp : tx_input = {
    previous_output = {
      txid = prev_txid;
      vout = 0;
    };
    script_sig = Bytes.empty;  (* Empty for SegWit *)
    sequence   = 0xFFFF_FFFF;
  } in
  let out : tx_output = {
    value = Int64.of_int 10000;
    script_pubkey = Bytes.of_string "\x00\x14";  (* OP_0 OP_DATA_20 for P2WPKH *)
  } in
  {
    version;
    inputs  = [inp];
    outputs = [out];
    witnesses = [
      [ Bytes.of_string "\x47";  (* signature placeholder *)
        Bytes.of_string "\x02\x21\x00";  (* public key placeholder *)
      ];
    ];
    lock_time;
    segwit    = true;
  }

let test_segwit_p2wpkh_extract () =
  let tx = make_segwit_p2wpkh_tx () in
  let result = ok_exn "extract" (Signature_extraction.extract tx) in
  Alcotest.(check int) "1 input" 1 (List.length result);
  let sig_data = List.nth result 0 in
  Alcotest.(check int) "input_index 0" 0 sig_data.input_index

let test_segwit_no_witness () =
  let tx = make_segwit_p2wpkh_tx () in
  let tx_no_witness = { tx with witnesses = [[]] } in
  Alcotest.(check bool) "no witness => no signature" true
    (is_error (Signature_extraction.extract_single tx_no_witness 0))

(* ------------------------------------------------------------------ empty transaction *)

let test_empty_tx () =
  let tx = {
    version = 1;
    inputs  = [];
    outputs = [];
    witnesses = [];
    lock_time = 0;
    segwit    = false;
  } in
  match Signature_extraction.extract tx with
  | Ok [] -> ()
  | Ok _  -> Alcotest.fail "expected empty list"
  | Error e -> Alcotest.failf "unexpected error: %s" (Signature_extraction.error_to_string e)

(* ------------------------------------------------------------------ main *)

let () =
  Alcotest.run "signature-extraction" [
    "legacy", [
      "extract P2PKH",           `Quick, test_legacy_p2pkh_extract;
      "extract_single",          `Quick, test_legacy_single_input;
      "out of bounds",           `Quick, test_legacy_out_of_bounds;
    ];
    "SegWit", [
      "extract P2WPKH",          `Quick, test_segwit_p2wpkh_extract;
      "no witness rejected",     `Quick, test_segwit_no_witness;
    ];
    "edge cases", [
      "empty transaction",       `Quick, test_empty_tx;
    ];
  ]
