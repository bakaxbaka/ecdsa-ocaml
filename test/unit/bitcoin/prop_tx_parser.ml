(* test/unit/bitcoin/prop_tx_parser.ml
   Property-based tests for the Bitcoin transaction parser.

   Core property:
     P1. No arbitrary byte sequence causes an uncaught exception.
         Malformed input must always return Error, never raise.

   Supporting properties:
     P2. Any prefix of a valid transaction fails to parse (truncation safety).
     P3. A valid transaction with one extra byte appended fails with Trailing_data.
     P4. CompactSize round-trip: values in [0..252] encode as single byte.
*)

open QCheck

(* ------------------------------------------------------------------ generators *)

let gen_bytes =
  Gen.map Bytes.of_string
    (Gen.string_size (Gen.int_range 0 512))

(* Minimal valid legacy transaction with empty scriptSig and scriptPubKey.
   version=1, 1 coinbase input, 1 output (0 sat), locktime=0 *)
let minimal_valid_tx_bytes =
  let b = Buffer.create 64 in
  (* version: 1 LE *)
  Buffer.add_string b "\x01\x00\x00\x00";
  (* vin_count: 1 *)
  Buffer.add_char b '\x01';
  (* prev txid: 32 zeros *)
  Buffer.add_string b (String.make 32 '\x00');
  (* prev vout: 0xFFFFFFFF *)
  Buffer.add_string b "\xff\xff\xff\xff";
  (* scriptSig len: 0 *)
  Buffer.add_char b '\x00';
  (* sequence: 0xFFFFFFFF *)
  Buffer.add_string b "\xff\xff\xff\xff";
  (* vout_count: 1 *)
  Buffer.add_char b '\x01';
  (* value: 0 sat *)
  Buffer.add_string b "\x00\x00\x00\x00\x00\x00\x00\x00";
  (* scriptPubKey len: 0 *)
  Buffer.add_char b '\x00';
  (* locktime: 0 *)
  Buffer.add_string b "\x00\x00\x00\x00";
  Bytes.of_string (Buffer.contents b)

(* ------------------------------------------------------------------ properties *)

(* P1: Parser never raises on arbitrary input — only returns Ok or Error. *)
let prop_no_exception =
  Test.make ~name:"P1: arbitrary bytes never raise"
    ~count:10000
    (make gen_bytes)
    (fun b ->
      (* We test that the call does not raise by catching everything. *)
      match (try Ok (Parser.of_bytes b) with e -> Error (Printexc.to_string e)) with
      | Ok (Ok _)    -> true  (* parsed successfully *)
      | Ok (Error _) -> true  (* returned parse error — expected *)
      | Error msg    ->
        Printf.printf "EXCEPTION: %s\n%!" msg;
        false)

(* P2: Any strict prefix of a valid transaction fails. *)
let prop_prefix_truncates =
  Test.make ~name:"P2: prefix of valid tx truncates"
    ~count:200
    (make (Gen.int_range 0 (Bytes.length minimal_valid_tx_bytes - 1)))
    (fun prefix_len ->
      let prefix = Bytes.sub minimal_valid_tx_bytes 0 prefix_len in
      match Parser.of_bytes prefix with
      | Error _ -> true
      | Ok _    -> false  (* a strict prefix should never parse successfully *))

(* P3: Valid tx with one extra byte appended fails with Trailing_data. *)
let prop_trailing_byte_rejected =
  Test.make ~name:"P3: trailing byte rejected"
    (make (Gen.map Char.chr (Gen.int_range 0 255)))
    (fun extra ->
      let extra_b = Bytes.make 1 extra in
      let extended = Bytes.cat minimal_valid_tx_bytes extra_b in
      match Parser.of_bytes extended with
      | Error (Common.Parse_error.Trailing_data _) -> true
      | Error _ -> false  (* wrong error variant *)
      | Ok _    -> false  (* trailing byte silently accepted — wrong *))

(* P4: CompactSize canonical encoding: values 0..252 round-trip as single byte.
   We verify indirectly: a scriptSig of length n (0<=n<=252) parses correctly
   when encoded with compact_size n (single byte 0xNN). *)
let prop_compact_size_single_byte =
  Test.make ~name:"P4: CompactSize 0..252 single-byte canonical"
    ~count:253
    (make (Gen.int_range 0 252))
    (fun n ->
      let script = Bytes.make n '\xaa' in
      let b = Buffer.create (64 + n) in
      Buffer.add_string b "\x01\x00\x00\x00";  (* version 1 *)
      Buffer.add_char b '\x01';                (* vin_count *)
      Buffer.add_string b (String.make 32 '\x00');  (* txid *)
      Buffer.add_string b "\xff\xff\xff\xff";  (* vout *)
      Buffer.add_char b (Char.chr n);          (* scriptSig len: single byte *)
      Buffer.add_bytes b script;               (* scriptSig *)
      Buffer.add_string b "\xff\xff\xff\xff";  (* sequence *)
      Buffer.add_char b '\x01';                (* vout_count *)
      Buffer.add_string b "\x00\x00\x00\x00\x00\x00\x00\x00";  (* value *)
      Buffer.add_char b '\x00';                (* scriptPubKey len *)
      Buffer.add_string b "\x00\x00\x00\x00"; (* locktime *)
      let tx_bytes = Bytes.of_string (Buffer.contents b) in
      match Parser.of_bytes tx_bytes with
      | Ok tx ->
        let script_parsed = (List.nth tx.inputs 0).script_sig in
        Bytes.equal script script_parsed
      | Error _ -> false)

(* ------------------------------------------------------------------ main *)

let () =
  let tests = [
    prop_no_exception;
    prop_prefix_truncates;
    prop_trailing_byte_rejected;
    prop_compact_size_single_byte;
  ] in
  Alcotest.run "bitcoin-tx-parser-properties"
    [ "properties", List.map QCheck_alcotest.to_alcotest tests ]
