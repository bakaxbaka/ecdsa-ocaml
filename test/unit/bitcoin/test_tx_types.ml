(* test/unit/bitcoin/test_tx_types.ml
   Unit tests for Bitcoin transaction domain types. *)

let ok_exn = function Ok v -> v | Error _ -> failwith "unexpected Error"
let is_error = function Error _ -> true | Ok _ -> false

(* ------------------------------------------------------------------ txid display/internal order *)

(* The Genesis block coinbase txid in display hex (as shown by block explorers
   and bitcoin-cli).  This is a well-known fixed value. *)
let genesis_txid_display =
  "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"

(* The same txid in internal byte order is the display bytes reversed. *)
let genesis_txid_internal =
  (* Reverse the 32-byte sequence of the display hex. *)
  let display_bytes =
    let n = String.length genesis_txid_display / 2 in
    let b = Bytes.create n in
    for i = 0 to n - 1 do
      let hi = Scanf.sscanf (String.sub genesis_txid_display (i*2) 1) "%x" Fun.id in
      let lo = Scanf.sscanf (String.sub genesis_txid_display (i*2+1) 1) "%x" Fun.id in
      Bytes.set b i (Char.chr (hi lsl 4 lor lo))
    done;
    b
  in
  let internal = Bytes.create 32 in
  for i = 0 to 31 do
    Bytes.set internal i (Bytes.get display_bytes (31 - i))
  done;
  internal

let test_txid_round_trip () =
  let internal = ok_exn (Types.txid_of_display_hex genesis_txid_display) in
  Alcotest.(check bool) "internal bytes match" true
    (Bytes.equal internal genesis_txid_internal);
  let back = Types.txid_to_display_hex internal in
  Alcotest.(check string) "display roundtrip" genesis_txid_display back

let test_txid_bad_length () =
  Alcotest.(check bool) "too short rejected" true
    (is_error (Types.txid_of_display_hex "deadbeef"));
  Alcotest.(check bool) "too long rejected" true
    (is_error (Types.txid_of_display_hex
      (genesis_txid_display ^ "00")))

let test_txid_invalid_chars () =
  (* Replace last two chars with an invalid character. *)
  let bad = String.sub genesis_txid_display 0 62 ^ "zz" in
  Alcotest.(check bool) "invalid chars rejected" true
    (is_error (Types.txid_of_display_hex bad))

(* ------------------------------------------------------------------ coinbase *)

let test_coinbase_txid () =
  Alcotest.(check int) "coinbase_txid is 32 bytes" 32
    (Bytes.length Types.coinbase_txid);
  (* Every byte must be 0x00. *)
  let all_zero = Bytes.for_all (fun c -> Char.code c = 0) Types.coinbase_txid in
  Alcotest.(check bool) "coinbase_txid all zeros" true all_zero

let test_is_coinbase () =
  let coinbase_input : Types.tx_input = {
    previous_output = { txid = Types.coinbase_txid; vout = 0xFFFF_FFFF };
    script_sig      = Bytes.of_string "\x03\x4e\x01\x04";
    sequence        = 0xFFFF_FFFF;
  } in
  Alcotest.(check bool) "coinbase input detected" true
    (Types.is_coinbase coinbase_input);
  (* Change vout: no longer coinbase. *)
  let not_coinbase = { coinbase_input with
    previous_output = { coinbase_input.previous_output with vout = 0 }
  } in
  Alcotest.(check bool) "non-coinbase vout" false
    (Types.is_coinbase not_coinbase);
  (* Change txid: no longer coinbase. *)
  let non_zero_txid = Bytes.make 32 '\x01' in
  let not_coinbase2 = { coinbase_input with
    previous_output = { txid = non_zero_txid; vout = 0xFFFF_FFFF }
  } in
  Alcotest.(check bool) "non-zero txid" false
    (Types.is_coinbase not_coinbase2)

(* ------------------------------------------------------------------ equality *)

let make_output value script : Types.tx_output =
  { value = Int64.of_int value; script_pubkey = Bytes.of_string script }

let make_input txid vout script seq : Types.tx_input =
  let txid_bytes =
    ok_exn (Types.txid_of_display_hex txid)
  in
  { previous_output = { txid = txid_bytes; vout };
    script_sig = Bytes.of_string script;
    sequence = seq }

let sample_txid = String.make 64 '0'  (* 32 zero bytes in display hex *)

let sample_tx : Types.transaction = {
  version   = 1;
  inputs    = [ make_input sample_txid 0 "" 0xFFFF_FFFF ];
  outputs   = [ make_output 5000000000 "\x76\xa9\x14" ];
  witnesses = [];
  lock_time = 0;
  segwit    = false;
}

let test_equal_transaction_reflexive () =
  Alcotest.(check bool) "reflexive" true
    (Types.equal_transaction sample_tx sample_tx)

let test_equal_transaction_different_version () =
  let tx2 = { sample_tx with version = 2 } in
  Alcotest.(check bool) "version differs" false
    (Types.equal_transaction sample_tx tx2)

let test_equal_transaction_different_output_value () =
  let outputs2 = [ make_output 1 "\x76\xa9\x14" ] in
  let tx2 = { sample_tx with outputs = outputs2 } in
  Alcotest.(check bool) "output value differs" false
    (Types.equal_transaction sample_tx tx2)

let test_segwit_flag () =
  let segwit_tx = { sample_tx with segwit = true;
    witnesses = [ [ Bytes.of_string "\x01\x02" ] ] } in
  Alcotest.(check bool) "segwit differs from legacy" false
    (Types.equal_transaction sample_tx segwit_tx)

(* ------------------------------------------------------------------ output value range *)

let test_output_value_max_supply () =
  (* 20_999_999.97690000 BTC = 2_099_999_997_690_000 satoshis *)
  let max_sat = Int64.of_string "2099999997690000" in
  let out : Types.tx_output = { value = max_sat; script_pubkey = Bytes.empty } in
  Alcotest.(check int64) "max supply stored exactly" max_sat out.value

(* ------------------------------------------------------------------ main *)

let () =
  Alcotest.run "bitcoin-tx-types" [
    "txid", [
      "round-trip display<->internal", `Quick, test_txid_round_trip;
      "bad length rejected",           `Quick, test_txid_bad_length;
      "invalid chars rejected",        `Quick, test_txid_invalid_chars;
    ];
    "coinbase", [
      "coinbase_txid is 32 zero bytes", `Quick, test_coinbase_txid;
      "is_coinbase detection",          `Quick, test_is_coinbase;
    ];
    "equality", [
      "reflexive",               `Quick, test_equal_transaction_reflexive;
      "version differs",         `Quick, test_equal_transaction_different_version;
      "output value differs",    `Quick, test_equal_transaction_different_output_value;
      "segwit flag differs",     `Quick, test_segwit_flag;
    ];
    "value range", [
      "max supply stored exactly", `Quick, test_output_value_max_supply;
    ];
  ]
