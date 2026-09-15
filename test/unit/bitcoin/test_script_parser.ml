(* test/unit/bitcoin/test_script_parser.ml
   Unit tests for the Bitcoin Script parser.

   Tests construct expected Script.t values directly and compare against
   Parser.of_bytes / Parser.of_hex output.

   Coverage:
   - Empty script
   - OP_0 (0x00)
   - Direct push opcodes: single byte, multi-byte, max (75 bytes, opcode 0x4b)
   - OP_PUSHDATA1 (0x4c)
   - OP_PUSHDATA2 (0x4d)
   - OP_PUSHDATA4 (0x4e)
   - OP_1NEGATE (0x4f) and OP_RESERVED (0x50)
   - OP_1..OP_16 (0x51..0x60)
   - Non-push opcodes: OP_DUP, OP_CHECKSIG, arbitrary bytes
   - Mixed script (typical P2PKH scriptPubKey)
   - Mixed script (typical P2PKH scriptSig)
   - of_hex with and without 0x prefix
   - Truncation: direct push, PUSHDATA1/2/4 length field, PUSHDATA1/2/4 data
   - PUSHDATA4 declared length exceeds buffer
   - All 256 single-byte opcodes parse without exception
*)

let ok_exn lbl = function
  | Ok v    -> v
  | Error e -> Alcotest.failf "%s: unexpected Error: %s" lbl
                 (Common.Parse_error.to_string e)

let is_error = function Error _ -> true | Ok _ -> false

(* ------------------------------------------------------------------ helpers *)

(* Hex-encode a raw string for use with Parser.of_hex *)
let _hex_of_string s =
  let buf = Buffer.create (String.length s * 2) in
  String.iter (fun c ->
    Buffer.add_string buf (Printf.sprintf "%02x" (Char.code c))) s;
  Buffer.contents buf

let bytes_of_hex h =
  let n = String.length h / 2 in
  let b = Bytes.create n in
  for i = 0 to n - 1 do
    let hi = Scanf.sscanf (String.sub h (i*2)   1) "%x" Fun.id in
    let lo = Scanf.sscanf (String.sub h (i*2+1) 1) "%x" Fun.id in
    Bytes.set b i (Char.chr (hi lsl 4 lor lo))
  done;
  b

(* Build a raw byte buffer from a hex string *)
let buf h = bytes_of_hex h

(* ------------------------------------------------------------------ empty *)

let test_empty_script () =
  let result = ok_exn "empty" (Parser.of_bytes Bytes.empty) in
  Alcotest.(check int) "empty length" 0 (List.length result);
  Alcotest.(check bool) "equal empty" true (Script.equal result Script.empty)

(* ------------------------------------------------------------------ OP_0 *)

let test_op_0 () =
  let result = ok_exn "op0" (Parser.of_bytes (buf "00")) in
  Alcotest.(check int) "1 instruction" 1 (List.length result);
  let instr = List.nth result 0 in
  Alcotest.(check bool) "is push"    true  (Script.is_push instr);
  Alcotest.(check int)  "opcode 0x00" 0x00 (Script.opcode_of instr);
  Alcotest.(check bytes) "empty data" Bytes.empty (Script.data_of instr)

(* ------------------------------------------------------------------ direct push *)

let test_direct_push_1_byte () =
  (* 0x01 0xab: push 1 byte *)
  let result = ok_exn "dp1" (Parser.of_bytes (buf "01ab")) in
  Alcotest.(check int) "1 instr" 1 (List.length result);
  let instr = List.nth result 0 in
  Alcotest.(check int) "opcode 0x01" 0x01 (Script.opcode_of instr);
  Alcotest.(check bytes) "data" (Bytes.make 1 '\xab') (Script.data_of instr)

let test_direct_push_4_bytes () =
  (* 0x04 deadbeef *)
  let result = ok_exn "dp4" (Parser.of_bytes (buf "04deadbeef")) in
  let instr = List.nth result 0 in
  Alcotest.(check int) "opcode 0x04" 0x04 (Script.opcode_of instr);
  Alcotest.(check int) "data length" 4 (Bytes.length (Script.data_of instr))

let test_direct_push_max () =
  (* opcode 0x4b = 75: push 75 bytes *)
  let data = String.make 75 '\xcc' in
  let raw  = Bytes.cat (Bytes.make 1 '\x4b') (Bytes.of_string data) in
  let result = ok_exn "dp75" (Parser.of_bytes raw) in
  let instr = List.nth result 0 in
  Alcotest.(check int) "opcode 0x4b" 0x4b (Script.opcode_of instr);
  Alcotest.(check int) "data length 75" 75 (Bytes.length (Script.data_of instr))

(* ------------------------------------------------------------------ OP_PUSHDATA1 *)

let test_pushdata1 () =
  (* 0x4c 0x03 aabbcc *)
  let result = ok_exn "pd1" (Parser.of_bytes (buf "4c03aabbcc")) in
  let instr = List.nth result 0 in
  Alcotest.(check int) "opcode 0x4c" 0x4c (Script.opcode_of instr);
  Alcotest.(check int) "data length 3" 3 (Bytes.length (Script.data_of instr));
  Alcotest.(check bytes) "data bytes"
    (Bytes.of_string "\xaa\xbb\xcc") (Script.data_of instr)

let test_pushdata1_zero_len () =
  (* 0x4c 0x00: push 0 bytes — valid, empty data *)
  let result = ok_exn "pd1_zero" (Parser.of_bytes (buf "4c00")) in
  let instr = List.nth result 0 in
  Alcotest.(check int) "opcode 0x4c" 0x4c (Script.opcode_of instr);
  Alcotest.(check bytes) "empty data" Bytes.empty (Script.data_of instr)

(* ------------------------------------------------------------------ OP_PUSHDATA2 *)

let test_pushdata2 () =
  (* 0x4d 0x04 0x00: 4-byte data (len=4 LE), then 4 bytes *)
  let result = ok_exn "pd2" (Parser.of_bytes (buf "4d0400aabbccdd")) in
  let instr = List.nth result 0 in
  Alcotest.(check int) "opcode 0x4d" 0x4d (Script.opcode_of instr);
  Alcotest.(check int) "data length 4" 4 (Bytes.length (Script.data_of instr))

(* ------------------------------------------------------------------ OP_PUSHDATA4 *)

let test_pushdata4 () =
  (* 0x4e 0x02 0x00 0x00 0x00: len=2 LE, then 2 bytes *)
  let result = ok_exn "pd4" (Parser.of_bytes (buf "4e02000000aabb")) in
  let instr = List.nth result 0 in
  Alcotest.(check int) "opcode 0x4e" 0x4e (Script.opcode_of instr);
  Alcotest.(check int) "data length 2" 2 (Bytes.length (Script.data_of instr))

(* ------------------------------------------------------------------ OP_1NEGATE and OP_RESERVED *)

let test_op_1negate () =
  let result = ok_exn "1negate" (Parser.of_bytes (buf "4f")) in
  let instr = List.nth result 0 in
  Alcotest.(check bool) "is push" true (Script.is_push instr);
  Alcotest.(check int) "opcode 0x4f" 0x4f (Script.opcode_of instr);
  Alcotest.(check bytes) "empty data" Bytes.empty (Script.data_of instr)

let test_op_reserved () =
  (* 0x50: OP_RESERVED — bare Opcode, not a push *)
  let result = ok_exn "reserved" (Parser.of_bytes (buf "50")) in
  let instr = List.nth result 0 in
  Alcotest.(check bool) "not push" false (Script.is_push instr);
  Alcotest.(check int) "opcode 0x50" 0x50 (Script.opcode_of instr)

(* ------------------------------------------------------------------ OP_1..OP_16 *)

let test_op_1_through_16 () =
  for n = 0 to 15 do
    let op = Script.op_1 + n in
    let raw = Bytes.make 1 (Char.chr op) in
    match Parser.of_bytes raw with
    | Error e ->
      Alcotest.failf "OP_%d parse failed: %s" (n+1)
        (Common.Parse_error.to_string e)
    | Ok instrs ->
      let instr = List.nth instrs 0 in
      if Script.opcode_of instr <> op then
        Alcotest.failf "OP_%d: opcode_of = 0x%02x, expected 0x%02x"
          (n+1) (Script.opcode_of instr) op;
      if not (Script.is_push instr) then
        Alcotest.failf "OP_%d: expected Push_data" (n+1);
      if not (Bytes.equal Bytes.empty (Script.data_of instr)) then
        Alcotest.failf "OP_%d: expected empty data" (n+1)
  done

(* ------------------------------------------------------------------ non-push opcodes *)

let test_op_checksig () =
  let result = ok_exn "checksig" (Parser.of_bytes (buf "ac")) in
  let instr = List.nth result 0 in
  Alcotest.(check bool) "not push"    false (Script.is_push instr);
  Alcotest.(check int)  "opcode 0xac" 0xac  (Script.opcode_of instr)

let test_all_single_byte_opcodes () =
  (* For every opcode byte 0x00..0xFF, parsing a single-byte buffer must
     either succeed with 1 instruction (opcodes that require no following data)
     or return a Truncated error (push opcodes that require data bytes).
     No byte value must cause an uncaught exception. *)
  for b = 0 to 255 do
    let raw = Bytes.make 1 (Char.chr b) in
    let needs_data =
      (* direct push 0x01..0x4b need N following bytes *)
      (b >= 0x01 && b <= 0x4b) ||
      (* PUSHDATA1/2/4 need at least their length field *)
      b = 0x4c || b = 0x4d || b = 0x4e
    in
    match Parser.of_bytes raw with
    | Error (Common.Parse_error.Truncated _) when needs_data ->
      () (* expected: push opcode with no data is correctly truncated *)
    | Error e ->
      Alcotest.failf "byte 0x%02x: unexpected error: %s" b
        (Common.Parse_error.to_string e)
    | Ok instrs ->
      if needs_data then
        Alcotest.failf "byte 0x%02x: expected Truncated, got Ok" b
      else if List.length instrs <> 1 then
        Alcotest.failf "byte 0x%02x: expected 1 instruction, got %d"
          b (List.length instrs)
  done

(* ------------------------------------------------------------------ mixed scripts *)

(* Typical P2PKH scriptPubKey:
   OP_DUP OP_HASH160 OP_DATA_20 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
   76 a9 14 <20 bytes> 88 ac
*)
let test_p2pkh_scriptpubkey () =
  let hash = String.make 20 '\x42' in
  let raw  = "\x76\xa9\x14" ^ hash ^ "\x88\xac" in
  let result = ok_exn "p2pkh_spk" (Parser.of_bytes (Bytes.of_string raw)) in
  Alcotest.(check int) "5 instructions" 5 (List.length result);
  (* OP_DUP *)
  Alcotest.(check int) "op_dup"  0x76 (Script.opcode_of (List.nth result 0));
  (* OP_HASH160 *)
  Alcotest.(check int) "op_hash160" 0xa9 (Script.opcode_of (List.nth result 1));
  (* OP_DATA_20 *)
  let push20 = List.nth result 2 in
  Alcotest.(check bool) "is push" true (Script.is_push push20);
  Alcotest.(check int)  "data len 20" 20 (Bytes.length (Script.data_of push20));
  (* OP_EQUALVERIFY *)
  Alcotest.(check int) "op_equalverify" 0x88 (Script.opcode_of (List.nth result 3));
  (* OP_CHECKSIG *)
  Alcotest.(check int) "op_checksig" 0xac (Script.opcode_of (List.nth result 4))

(* Minimal P2PKH scriptSig:
   OP_DATA_47 <sig> OP_DATA_33 <pubkey>
   2f <47 bytes> 21 <33 bytes>
*)
let test_p2pkh_scriptsig () =
  let sig_bytes = String.make 71 '\xde' in  (* 0x47 = 71 *)
  let pub_bytes = String.make 33 '\x02' in  (* 0x21 = 33 *)
  let raw = "\x47" ^ sig_bytes ^ "\x21" ^ pub_bytes in
  let result = ok_exn "p2pkh_ss" (Parser.of_bytes (Bytes.of_string raw)) in
  Alcotest.(check int) "2 instructions" 2 (List.length result);
  Alcotest.(check int) "sig opcode 0x47" 0x47
    (Script.opcode_of (List.nth result 0));
  Alcotest.(check int) "sig length 71" 71
    (Bytes.length (Script.data_of (List.nth result 0)));
  Alcotest.(check int) "pub opcode 0x21" 0x21
    (Script.opcode_of (List.nth result 1));
  Alcotest.(check int) "pub length 33" 33
    (Bytes.length (Script.data_of (List.nth result 1)))

(* ------------------------------------------------------------------ of_hex *)

let test_of_hex_no_prefix () =
  let result = ok_exn "hex_no_prefix" (Parser.of_hex "ac") in
  Alcotest.(check int) "opcode 0xac" 0xac
    (Script.opcode_of (List.nth result 0))

let test_of_hex_with_prefix () =
  let result = ok_exn "hex_prefix" (Parser.of_hex "0xac") in
  Alcotest.(check int) "opcode 0xac" 0xac
    (Script.opcode_of (List.nth result 0))

(* ------------------------------------------------------------------ truncation *)

let test_truncate_direct_push () =
  (* opcode 0x04 but only 2 bytes of data follow *)
  Alcotest.(check bool) "truncated direct push" true
    (is_error (Parser.of_bytes (buf "04aabb")))

let test_truncate_pushdata1_length () =
  (* 0x4c but no length byte follows *)
  Alcotest.(check bool) "truncated PUSHDATA1 length" true
    (is_error (Parser.of_bytes (buf "4c")))

let test_truncate_pushdata1_data () =
  (* 0x4c 0x03 but only 1 byte of data *)
  Alcotest.(check bool) "truncated PUSHDATA1 data" true
    (is_error (Parser.of_bytes (buf "4c03aa")))

let test_truncate_pushdata2_length () =
  (* 0x4d but only 1 byte of length field *)
  Alcotest.(check bool) "truncated PUSHDATA2 length" true
    (is_error (Parser.of_bytes (buf "4d01")))

let test_truncate_pushdata2_data () =
  (* 0x4d 0x03 0x00 but no data *)
  Alcotest.(check bool) "truncated PUSHDATA2 data" true
    (is_error (Parser.of_bytes (buf "4d0300")))

let test_truncate_pushdata4_length () =
  (* 0x4e but only 2 bytes of length field *)
  Alcotest.(check bool) "truncated PUSHDATA4 length" true
    (is_error (Parser.of_bytes (buf "4e0100")))

let test_pushdata4_length_exceeds_buffer () =
  (* 0x4e declares length=100 but only 2 bytes follow *)
  let raw = Bytes.cat
    (Bytes.of_string "\x4e\x64\x00\x00\x00") (* PUSHDATA4, len=100 *)
    (Bytes.of_string "\xaa\xbb") in           (* only 2 bytes *)
  Alcotest.(check bool) "PUSHDATA4 len > remaining" true
    (is_error (Parser.of_bytes raw))

(* ------------------------------------------------------------------ main *)

let () =
  Alcotest.run "script-parser" [
    "empty", [
      "empty script",                `Quick, test_empty_script;
    ];
    "OP_0", [
      "OP_0 push",                   `Quick, test_op_0;
    ];
    "direct push", [
      "1-byte push",                 `Quick, test_direct_push_1_byte;
      "4-byte push",                 `Quick, test_direct_push_4_bytes;
      "max 75-byte push",            `Quick, test_direct_push_max;
    ];
    "PUSHDATA", [
      "PUSHDATA1 3 bytes",           `Quick, test_pushdata1;
      "PUSHDATA1 zero length",       `Quick, test_pushdata1_zero_len;
      "PUSHDATA2",                   `Quick, test_pushdata2;
      "PUSHDATA4",                   `Quick, test_pushdata4;
    ];
    "implicit value push", [
      "OP_1NEGATE",                  `Quick, test_op_1negate;
      "OP_RESERVED (non-push)",      `Quick, test_op_reserved;
      "OP_1 through OP_16",          `Quick, test_op_1_through_16;
    ];
    "non-push opcodes", [
      "OP_CHECKSIG",                 `Quick, test_op_checksig;
      "all 256 single bytes",        `Quick, test_all_single_byte_opcodes;
    ];
    "mixed scripts", [
      "P2PKH scriptPubKey",          `Quick, test_p2pkh_scriptpubkey;
      "P2PKH scriptSig",             `Quick, test_p2pkh_scriptsig;
    ];
    "of_hex", [
      "no prefix",                   `Quick, test_of_hex_no_prefix;
      "0x prefix",                   `Quick, test_of_hex_with_prefix;
    ];
    "truncation", [
      "direct push data",            `Quick, test_truncate_direct_push;
      "PUSHDATA1 length field",      `Quick, test_truncate_pushdata1_length;
      "PUSHDATA1 data",              `Quick, test_truncate_pushdata1_data;
      "PUSHDATA2 length field",      `Quick, test_truncate_pushdata2_length;
      "PUSHDATA2 data",              `Quick, test_truncate_pushdata2_data;
      "PUSHDATA4 length field",      `Quick, test_truncate_pushdata4_length;
      "PUSHDATA4 len > buffer",      `Quick, test_pushdata4_length_exceeds_buffer;
    ];
  ]
