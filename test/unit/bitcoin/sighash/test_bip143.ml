(* test/unit/bitcoin/sighash/test_bip143.ml
   Unit tests for BIP143 (SegWit) SIGHASH computation.

   Test strategy:
   1. Known Bitcoin transaction vectors
   2. Synthetic transaction tests for all SIGHASH types and ANYONECANPAY
   3. Error path: index out of bounds, invalid sighash type
   4. SIGHASH_SINGLE with input_index >= n_outputs
*)

open Types
open Bip143

let ok_exn lbl = function
  | Ok v    -> v
  | Error e ->
    let msg = match e with
      | `Index_out_of_bounds  -> "index out of bounds"
      | `Invalid_sighash_type -> "invalid sighash type"
    in
    Alcotest.failf "%s: unexpected Error: %s" lbl msg

let is_error = function Error _ -> true | Ok _ -> false

let hex_of_bytes b =
  Bytes.fold_left (fun acc c -> acc ^ Printf.sprintf "%02x" (Char.code c)) "" b

let check_digest label expected actual =
  Alcotest.(check string) label expected (hex_of_bytes actual)

let bytes_of_hex h =
  let n = String.length h / 2 in
  let bytes = Bytes.create n in
  for i = 0 to n - 1 do
    let byte = Scanf.sscanf (String.sub h (i * 2) 2) "%x" Fun.id in
    Bytes.set bytes i (Char.chr byte)
  done;
  bytes

(* ------------------------------------------------------------------ helpers *)

(* Build a minimal SegWit transaction with n_inputs inputs and n_outputs outputs. *)
let make_segwit_tx ?(version=1) ?(lock_time=0) n_inputs n_outputs =
  let make_input i : tx_input = {
    previous_output = {
      txid = Bytes.make 32 (Char.chr i);
      vout = i;
    };
    script_sig = Bytes.empty;  (* empty for SegWit *)
    sequence   = 0xFFFF_FFFF;
  } in
  let make_output i : tx_output = {
    value         = Int64.of_int (i * 1000);
    script_pubkey = Bytes.make 5 (Char.chr (0x76 + i));  (* arbitrary *)
  } in
  {
    version;
    inputs    = List.init n_inputs  make_input;
    outputs   = List.init n_outputs make_output;
    witnesses = [];  (* witnesses not needed for sighash computation *)
    lock_time;
    segwit    = true;  (* SegWit transaction *)
  }

(* ------------------------------------------------------------------ synthetic SIGHASH_ALL *)

let test_sighash_all_2in_2out () =
  let tx = make_segwit_tx 2 2 in
  let sc = Bytes.of_string "\x76\xa9\x14" in  (* OP_DUP OP_HASH160 OP_DATA_20 *)
  let value = Int64.of_int 50000 in
  (* Input 0 *)
  let h0 = ok_exn "all_2in_2out_i0" (Bip143.compute tx 0 sc value sighash_all) in
  (* Input 1 *)
  let h1 = ok_exn "all_2in_2out_i1" (Bip143.compute tx 1 sc value sighash_all) in
  Alcotest.(check int) "input 0: 32 bytes"  32 (Bytes.length h0);
  Alcotest.(check int) "input 1: 32 bytes"  32 (Bytes.length h1);
  Alcotest.(check bool) "inputs produce different hashes" false (Bytes.equal h0 h1)

let test_sighash_all_scriptcode_matters () =
  let tx = make_segwit_tx 1 1 in
  let sc1 = Bytes.of_string "\xac" in              (* OP_CHECKSIG *)
  let sc2 = Bytes.of_string "\x76\xa9\xac" in     (* different scriptCode *)
  let value = Int64.of_int 10000 in
  let h1 = ok_exn "sc1" (Bip143.compute tx 0 sc1 value sighash_all) in
  let h2 = ok_exn "sc2" (Bip143.compute tx 0 sc2 value sighash_all) in
  Alcotest.(check bool) "different scriptCode -> different hash" false
    (Bytes.equal h1 h2)

let test_sighash_all_value_matters () =
  let tx = make_segwit_tx 1 1 in
  let sc = Bytes.of_string "\xac" in
  let h1 = ok_exn "v1000" (Bip143.compute tx 0 sc (Int64.of_int 1000) sighash_all) in
  let h2 = ok_exn "v2000" (Bip143.compute tx 0 sc (Int64.of_int 2000) sighash_all) in
  Alcotest.(check bool) "different value -> different hash" false
    (Bytes.equal h1 h2)

(* ------------------------------------------------------------------ SIGHASH_NONE *)

let test_sighash_none () =
  let tx = make_segwit_tx 2 2 in
  let sc = Bytes.make 1 '\xac' in
  let value = Int64.of_int 10000 in
  let h_all  = ok_exn "all"  (Bip143.compute tx 0 sc value sighash_all)  in
  let h_none = ok_exn "none" (Bip143.compute tx 0 sc value sighash_none) in
  Alcotest.(check int) "none 32 bytes" 32 (Bytes.length h_none);
  Alcotest.(check bool) "all != none" false (Bytes.equal h_all h_none)

let test_sighash_none_zeroes_other_sequences () =
  (* Two transactions identical except input 1 sequence differs.
     SIGHASH_NONE zeroes hashSequence, so the other sequence is ignored. *)
  let tx1 = make_segwit_tx 2 2 in
  let tx2 = { tx1 with
    inputs = List.mapi (fun i inp ->
      if i = 1 then { inp with sequence = 0xDEADBEEF }
      else inp) tx1.inputs } in
  let sc = Bytes.make 1 '\xac' in
  let value = Int64.of_int 10000 in
  let h1 = ok_exn "none_seq1" (Bip143.compute tx1 0 sc value sighash_none) in
  let h2 = ok_exn "none_seq2" (Bip143.compute tx2 0 sc value sighash_none) in
  Alcotest.(check bool) "NONE: other input sequence ignored" true (Bytes.equal h1 h2)

(* ------------------------------------------------------------------ SIGHASH_SINGLE *)

let test_sighash_single () =
  let tx = make_segwit_tx 2 3 in
  let sc = Bytes.make 1 '\xac' in
  let value = Int64.of_int 10000 in
  let h = ok_exn "single" (Bip143.compute tx 0 sc value sighash_single) in
  Alcotest.(check int) "single 32 bytes" 32 (Bytes.length h)

let test_sighash_single_bug () =
  (* input_index >= n_outputs: BIP143 says hashOutputs is all zeros *)
  let tx = make_segwit_tx 3 2 in  (* 3 inputs, 2 outputs *)
  let sc = Bytes.make 1 '\xac' in
  let value = Int64.of_int 10000 in
  (* input_index=2 >= 2 outputs *)
  let result = ok_exn "single_bug" (Bip143.compute tx 2 sc value sighash_single) in
  Alcotest.(check int) "single_bug 32 bytes" 32 (Bytes.length result);
  (* The final sighash is NOT all zeros - it's hash256 of the full preimage.
     Only the hashOutputs part is zeros. We verify by checking the result
     has valid entropy (not all zeros). *)
  Alcotest.(check bool) "result not all zeros" false
    (Bytes.equal result (Bytes.make 32 '\x00'))

(* ------------------------------------------------------------------ ANYONECANPAY *)

let test_sighash_all_anyonecanpay () =
  let tx = make_segwit_tx 3 2 in
  let sc = Bytes.make 1 '\xac' in
  let value = Int64.of_int 10000 in
  let h_all = ok_exn "all" (Bip143.compute tx 0 sc value sighash_all) in
  let h_acp = ok_exn "acp"
    (Bip143.compute tx 0 sc value (sighash_all lor sighash_anyonecanpay)) in
  Alcotest.(check int) "acp 32 bytes" 32 (Bytes.length h_acp);
  (* ANYONECANPAY only includes the signed input -> different hash from ALL *)
  Alcotest.(check bool) "all != anyonecanpay" false (Bytes.equal h_all h_acp)

let test_sighash_none_anyonecanpay () =
  let tx = make_segwit_tx 2 2 in
  let sc = Bytes.make 1 '\xac' in
  let value = Int64.of_int 10000 in
  let h = ok_exn "none_acp"
    (Bip143.compute tx 0 sc value (sighash_none lor sighash_anyonecanpay)) in
  Alcotest.(check int) "none+acp 32 bytes" 32 (Bytes.length h)

let test_anyonecanpay_extra_inputs_ignored () =
  let tx1 = make_segwit_tx 1 1 in
  let tx2 = make_segwit_tx 2 1 in  (* same first input, one extra *)
  let sc  = Bytes.make 1 '\xac' in
  let value = Int64.of_int 10000 in
  let sht = sighash_all lor sighash_anyonecanpay in
  let h1 = ok_exn "acp1" (Bip143.compute tx1 0 sc value sht) in
  let h2 = ok_exn "acp2" (Bip143.compute tx2 0 sc value sht) in
  Alcotest.(check bool) "extra input ignored with ANYONECANPAY" true
    (Bytes.equal h1 h2)

(* ------------------------------------------------------------------ BIP143 reference vectors *)

let bip143_reference_tx =
  ok_exn "BIP143 P2SH-P2WSH transaction" (Parser.of_hex
    "010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e" ^
    "0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821" ^
    "ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c" ^
    "3ee41588ac00000000")

let bip143_reference_script_code =
  bytes_of_hex (
    "56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103" ^
    "b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113" ^
    "d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb8" ^
    "33092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d" ^
    "9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e" ^
    "07a55ad5dfbe673a9f01d9f0c19617681024306b56ae")

let test_bip143_reference_vectors () =
  let value = Int64.of_string "987654321" in
  let cases = [
    "SIGHASH_ALL", sighash_all,
      "185c0be5263dce5b4bb50a047973c1b6272bfbd0103a89444597dc40b248ee7c";
    "SIGHASH_NONE", sighash_none,
      "e9733bc60ea13c95c6527066bb975a2ff29a925e80aa14c213f686cbae5d2f36";
    "SIGHASH_SINGLE", sighash_single,
      "1e1f1c303dc025bd664acb72e583e933fae4cff9148bf78c157d1e8f78530aea";
    "SIGHASH_ALL|ANYONECANPAY", sighash_all lor sighash_anyonecanpay,
      "2a67f03e63a6a422125878b40b82da593be8d4efaafe88ee528af6e5a9955c6e";
    "SIGHASH_NONE|ANYONECANPAY", sighash_none lor sighash_anyonecanpay,
      "781ba15f3779d5542ce8ecb5c18716733a5ee42a6f51488ec96154934e2c890a";
    "SIGHASH_SINGLE|ANYONECANPAY", sighash_single lor sighash_anyonecanpay,
      "511e8e52ed574121fc1b654970395502128263f62662e076dc6baf05c2e6a99b";
  ] in
  List.iter (fun (label, sighash_type, expected) ->
    let actual = ok_exn label
      (Bip143.compute bip143_reference_tx 0 bip143_reference_script_code value sighash_type) in
    check_digest label expected actual
  ) cases

(* ------------------------------------------------------------------ error paths *)

let test_index_out_of_bounds () =
  let tx = make_segwit_tx 2 2 in
  let sc = Bytes.empty in
  let value = Int64.of_int 10000 in
  Alcotest.(check bool) "index -1" true
    (is_error (Bip143.compute tx (-1) sc value sighash_all));
  Alcotest.(check bool) "index 2" true
    (is_error (Bip143.compute tx 2 sc value sighash_all))

let test_invalid_sighash_type () =
  let tx = make_segwit_tx 1 1 in
  let sc = Bytes.empty in
  let value = Int64.of_int 10000 in
  Alcotest.(check bool) "type 0" true
    (is_error (Bip143.compute tx 0 sc value 0x00));
  Alcotest.(check bool) "type 4" true
    (is_error (Bip143.compute tx 0 sc value 0x04));
  Alcotest.(check bool) "type 0xff" true
    (is_error (Bip143.compute tx 0 sc value 0xff))

(* Type 0x81..0x83 (ANYONECANPAY variants) must be accepted *)
let test_anyonecanpay_variants_accepted () =
  let tx = make_segwit_tx 1 1 in
  let sc = Bytes.empty in
  let value = Int64.of_int 10000 in
  List.iter (fun sht ->
    Alcotest.(check bool) (Printf.sprintf "type 0x%02x accepted" sht) false
      (is_error (Bip143.compute tx 0 sc value sht))
  ) [0x81; 0x82; 0x83]

(* ------------------------------------------------------------------ version and locktime affect hash *)

let test_version_affects_hash () =
  let tx1 = make_segwit_tx ~version:1 1 1 in
  let tx2 = make_segwit_tx ~version:2 1 1 in
  let sc = Bytes.empty in
  let value = Int64.of_int 10000 in
  let h1 = ok_exn "v1" (Bip143.compute tx1 0 sc value sighash_all) in
  let h2 = ok_exn "v2" (Bip143.compute tx2 0 sc value sighash_all) in
  Alcotest.(check bool) "version affects hash" false (Bytes.equal h1 h2)

let test_locktime_affects_hash () =
  let tx1 = make_segwit_tx ~lock_time:0      1 1 in
  let tx2 = make_segwit_tx ~lock_time:500000 1 1 in
  let sc = Bytes.empty in
  let value = Int64.of_int 10000 in
  let h1 = ok_exn "lt0"  (Bip143.compute tx1 0 sc value sighash_all) in
  let h2 = ok_exn "lt1"  (Bip143.compute tx2 0 sc value sighash_all) in
  Alcotest.(check bool) "locktime affects hash" false (Bytes.equal h1 h2)

(* ------------------------------------------------------------------ main *)

let () =
  Alcotest.run "bip143-sighash" [
    "SIGHASH_ALL", [
      "2in 2out both inputs",         `Quick, test_sighash_all_2in_2out;
      "scriptCode matters",           `Quick, test_sighash_all_scriptcode_matters;
      "value matters",                `Quick, test_sighash_all_value_matters;
    ];
    "SIGHASH_NONE", [
      "produces different hash",      `Quick, test_sighash_none;
      "zeroes other sequences",       `Quick, test_sighash_none_zeroes_other_sequences;
    ];
    "SIGHASH_SINGLE", [
      "basic",                        `Quick, test_sighash_single;
      "input >= outputs (zeros)",     `Quick, test_sighash_single_bug;
    ];
    "ANYONECANPAY", [
      "ALL | ANYONECANPAY",           `Quick, test_sighash_all_anyonecanpay;
      "NONE | ANYONECANPAY",          `Quick, test_sighash_none_anyonecanpay;
      "extra inputs ignored",         `Quick, test_anyonecanpay_extra_inputs_ignored;
    ];
    "BIP143 reference vectors", [
      "all sighash modes",            `Quick, test_bip143_reference_vectors;
    ];
    "error paths", [
      "index out of bounds",          `Quick, test_index_out_of_bounds;
      "invalid sighash type",         `Quick, test_invalid_sighash_type;
      "ANYONECANPAY variants ok",     `Quick, test_anyonecanpay_variants_accepted;
    ];
    "field sensitivity", [
      "version affects hash",         `Quick, test_version_affects_hash;
      "locktime affects hash",        `Quick, test_locktime_affects_hash;
    ];
  ]
