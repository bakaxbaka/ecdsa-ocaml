(* test/unit/bitcoin/test_signature_extraction.ml
   Unit tests for signature extraction from Bitcoin transactions.

   Tests verify that signatures are correctly extracted from:
   - Legacy inputs with various push opcodes (OP_DATA_N, OP_PUSHDATA1/2/4)
   - SegWit inputs with empty dummy items (P2WSH-style multisig)
   - Malformed candidate DER payloads (strict error reporting)
*)

open Types
open Script

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

(* Strict DER signature for r = s = 1 followed by SIGHASH_ALL. *)
let valid_signature = Bytes.of_string "\x30\x06\x02\x01\x01\x02\x01\x01\x01"

(* ------------------------------------------------------------------ helpers *)

let bytes_of_hex h =
  let n = String.length h / 2 in
  let bytes = Bytes.create n in
  for i = 0 to n - 1 do
    let hi = int_of_char h.[i*2] - (if h.[i*2] <= '9' then Char.code '0' else Char.code 'a' - 10) in
    let lo = int_of_char h.[i*2+1] - (if h.[i*2+1] <= '9' then Char.code '0' else Char.code 'a' - 10) in
    Bytes.set bytes i (Char.chr (hi lsl 4 lor lo))
  done;
  bytes

let txid_of_hex h =
  let b = bytes_of_hex h in
  Bytes.sub b 0 32

let make_legacy_input ?(script_sig=Bytes.empty) () =
  {
    previous_output = {
      txid = txid_of_hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
      vout = 0;
    };
<<<<<<< HEAD
    script_sig;
    sequence = 0xFFFF_FFFF;
  }

let make_output ?(script_pubkey=Bytes.empty) () =
  {
=======
    script_sig = Bytes.cat (Bytes.of_string "\x09") valid_signature;
    sequence   = 0xFFFF_FFFF;
  } in
  let out : tx_output = {
>>>>>>> 701a8599c3226f1a1b23d1bd0b989e0f9e20a42c
    value = Int64.of_int 10000;
    script_pubkey;
  }

let make_tx ?(inputs=[]) ?(outputs=[]) ?(version=1) ?(lock_time=0) ?(segwit=false) () =
  {
    version;
    inputs;
    outputs;
    witnesses = [];
    lock_time;
    segwit;
  }

(* ------------------------------------------------------------------ legacy input *)

(* Test with minimal valid DER signature (71 bytes + 1 sighash = 72 bytes) *)
let test_legacy_p2pkh_extract () =
  let der_sig = bytes_of_hex
    "304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd4" ^
    "0220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901" in
  let inp = make_legacy_input ~script_sig:der_sig () in
  let tx = make_tx ~inputs:[inp] () in
  let result = ok_exn "extract" (Signature_extraction.extract tx) in
  Alcotest.(check int) "1 input" 1 (List.length result);
  let sig_data = List.nth result 0 in
  Alcotest.(check int) "input_index 0" 0 sig_data.input_index;
  Alcotest.(check int) "1 signature" 1 (List.length sig_data.signatures)

(* Test OP_PUSHDATA1 signature push *)
let test_legacy_pushdata1_signature () =
  (* OP_PUSHDATA1 0x48 followed by 72-byte signature + sighash *)
  let der_sig = bytes_of_hex
    "304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd4" ^
    "0220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901" in
  let pushdata1_sig = Bytes.cat (Bytes.of_string "\x4c") (Bytes.cat (Bytes.of_string "\x48") der_sig) in
  let inp = make_legacy_input ~script_sig:pushdata1_sig () in
  let tx = make_tx ~inputs:[inp] () in
  let result = ok_exn "pushdata1" (Signature_extraction.extract tx) in
  Alcotest.(check int) "1 signature" 1 (List.length result.(0).signatures)

(* Test malformed candidate - valid sighash but bad DER *)
let test_legacy_malformed_candidate () =
  (* Valid sighash byte but invalid DER structure *)
  let bad_der = bytes_of_hex "300102010101" in
  let inp = make_legacy_input ~script_sig:bad_der () in
  let tx = make_tx ~inputs:[inp] () in
  match Signature_extraction.extract tx with
  | Error (Invalid_der _) -> ()  (* Expected: strict DER failure *)
  | Ok _ -> Alcotest.fail "expected Invalid_der for malformed candidate"
  | Error e -> Alcotest.failf "unexpected error: %s" (Signature_extraction.error_to_string e)

(* Test public key extraction independent of signature *)
let test_legacy_public_key_extraction () =
  let der_sig = bytes_of_hex
    "304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd4" ^
    "0220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901" in
  let compressed_pubkey = bytes_of_hex
    "02210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba3" in
  (* scriptSig: signature + OP_DATA_33 pubkey *)
  let script_sig = Bytes.cat der_sig (Bytes.cat (Bytes.of_string "\x21") compressed_pubkey) in
  let inp = make_legacy_input ~script_sig () in
  let tx = make_tx ~inputs:[inp] () in
  let result = ok_exn "extract" (Signature_extraction.extract tx) in
  let sig_data = List.nth result 0 in
  Alcotest.(check int) "1 signature" 1 (List.length sig_data.signatures);
  Alcotest.(check bool) "public key present" true
    (sig_data.public_key <> None);
  Alcotest.(check bytes) "public key matches" compressed_pubkey
    (Option.value sig_data.public_key ~default:Bytes.empty)

let test_legacy_variable_length_push_extract () =
  let tx = make_legacy_p2pkh_tx () in
  let script_sig = Bytes.cat (Bytes.of_string "\x09") valid_signature in
  let tx = { tx with inputs = [{ (List.hd tx.inputs) with script_sig }] } in
  let result = ok_exn "variable length signature"
    (Signature_extraction.extract_single tx 0) in
  Alcotest.(check int) "signature extracted" 1 (List.length result.signatures)

(* ------------------------------------------------------------------ SegWit input *)

let make_segwit_tx ?(version=1) ?(lock_time=0) n_inputs n_outputs =
  let make_input i =
    {
      previous_output = {
        txid = Bytes.make 32 (Char.chr i);
        vout = i;
      };
      script_sig = Bytes.empty;
      sequence = 0xFFFF_FFFF;
    }
  in
  let make_output i =
    {
      value = Int64.of_int (i * 1000);
      script_pubkey = Bytes.make 5 (Char.chr (0x76 + i));
    }
  in
  {
    version;
<<<<<<< HEAD
    inputs  = List.init n_inputs make_input;
    outputs = List.init n_outputs make_output;
    witnesses = [];
=======
    inputs  = [inp];
    outputs = [out];
    witnesses = [
      [ valid_signature;
        Bytes.make 33 '\x02';
      ];
    ];
>>>>>>> 701a8599c3226f1a1b23d1bd0b989e0f9e20a42c
    lock_time;
    segwit  = true;
  }

let test_segwit_p2wpkh_extract () =
  let sig_bytes = bytes_of_hex
    "304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd4" ^
    "0220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901" in
  let pk_bytes = bytes_of_hex
    "02210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba3" in
  let inp = make_input ~script_sig:Bytes.empty ~sequence:0xFFFF_FFFF ()
  and tx = make_tx ~inputs:[inp] ~witnesses:[[sig_bytes; pk_bytes]] ~segwit:true () in
  let result = ok_exn "extract" (Signature_extraction.extract tx) in
  Alcotest.(check int) "1 input" 1 (List.length result);
  let sig_data = List.nth result 0 in
  Alcotest.(check int) "input_index 0" 0 sig_data.input_index;
  Alcotest.(check int) "1 signature" 1 (List.length sig_data.signatures);
  Alcotest.(check bytes) "public key found" pk_bytes
    (Option.value sig_data.public_key ~default:Bytes.empty)

(* P2WSH-style multisig with empty dummy item followed by signatures *)
let test_segwit_multisig_with_dummy () =
  let sig1 = bytes_of_hex
    "304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd4" ^
    "0220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901" in
  let sig2 = bytes_of_hex
    "30440220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09" ^
    "02204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd4101" in
  (* Witness: [dummy, sig1, sig2, script] *)
  let witness_stack = [Bytes.empty; sig1; sig2; bytes_of_hex "52ae"] in
  let tx = make_segwit_tx ~witnesses:[witness_stack] 1 1 in
  let result = ok_exn "multisig" (Signature_extraction.extract tx) in
  Alcotest.(check int) "1 input" 1 (List.length result);
  let sig_data = List.nth result 0 in
  Alcotest.(check int) "2 signatures (skipping dummy)" 2 (List.length sig_data.signatures)

let test_segwit_no_witness () =
  let tx = make_segwit_tx 1 1 in
  let tx_empty = { tx with witnesses = [[]] } in
  match Signature_extraction.extract_single tx_empty 0 with
  | Error No_signature -> ()  (* Expected *)
  | _ -> Alcotest.fail "expected No_signature for empty witness"

let test_segwit_scans_entire_witness_stack () =
  let tx = make_segwit_p2wpkh_tx () in
  let tx = { tx with witnesses = [[
    Bytes.of_string "not a signature";
    valid_signature;
    Bytes.of_string "also not a signature";
    valid_signature;
  ]] } in
  let result = ok_exn "witness signatures"
    (Signature_extraction.extract_single tx 0) in
  Alcotest.(check int) "all witness signatures extracted" 2
    (List.length result.signatures)

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
      "variable-length push",    `Quick, test_legacy_variable_length_push_extract;
    ];
    "SegWit", [
      "extract P2WPKH",          `Quick, test_segwit_p2wpkh_extract;
      "no witness rejected",     `Quick, test_segwit_no_witness;
      "scans entire witness",    `Quick, test_segwit_scans_entire_witness_stack;
    ];
    "edge cases", [
      "empty transaction",       `Quick, test_empty_tx;
    ];
  ]
