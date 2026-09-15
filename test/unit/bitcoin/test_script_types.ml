(* test/unit/bitcoin/test_script_types.ml
   Unit tests for Script.Script.
   All types are constructed directly — no parser is involved. *)

(* ------------------------------------------------------------------ helpers *)

let check_int    = Alcotest.(check int)
let check_bool   = Alcotest.(check bool)
let check_bytes  = Alcotest.(check bytes)

(* ------------------------------------------------------------------ empty script *)

let test_empty () =
  check_int  "empty length"  0 (List.length Script.empty);
  check_bool "empty equal"   true (Script.equal Script.empty Script.empty);
  check_bool "empty equal []" true (Script.equal Script.empty [])

(* ------------------------------------------------------------------ opcode constants *)

let test_opcode_values () =
  check_int "op_0"           0x00 Script.op_0;
  check_int "op_pushdata1"   0x4c Script.op_pushdata1;
  check_int "op_pushdata2"   0x4d Script.op_pushdata2;
  check_int "op_pushdata4"   0x4e Script.op_pushdata4;
  check_int "op_1negate"     0x4f Script.op_1negate;
  check_int "op_reserved"    0x50 Script.op_reserved;
  check_int "op_1"           0x51 Script.op_1;
  check_int "op_16"          0x60 Script.op_16;
  check_int "op_dup"         0x76 Script.op_dup;
  check_int "op_equalverify" 0x88 Script.op_equalverify;
  check_int "op_hash160"     0xa9 Script.op_hash160;
  check_int "op_checksig"    0xac Script.op_checksig;
  check_int "op_checkmultisig" 0xae Script.op_checkmultisig;
  check_int "op_return"      0x6a Script.op_return

(* ------------------------------------------------------------------ plain Opcode *)

let test_plain_opcode () =
  let instr = Script.Opcode Script.op_checksig in
  check_bool "not push"    false (Script.is_push instr);
  check_int  "opcode_of"   Script.op_checksig (Script.opcode_of instr);
  check_bytes "data_of"    Bytes.empty (Script.data_of instr)

let test_arbitrary_opcode () =
  (* Every byte in 0x00..0xFF is a valid opcode value. *)
  for b = 0 to 255 do
    let instr = Script.Opcode b in
    let got = Script.opcode_of instr in
    if got <> b then
      Alcotest.failf "opcode_of (Opcode 0x%02x) = 0x%02x, expected 0x%02x" b got b
  done

(* ------------------------------------------------------------------ Push_data: OP_0 *)

let test_op_0_push () =
  (* OP_0 pushes an empty byte vector. *)
  let instr = Script.Push_data { opcode = Script.op_0; data = Bytes.empty } in
  check_bool  "is push"     true  (Script.is_push instr);
  check_int   "opcode_of"   0x00  (Script.opcode_of instr);
  check_bytes "data empty"  Bytes.empty (Script.data_of instr)

(* ------------------------------------------------------------------ Push_data: direct push 0x01..0x4b *)

let test_direct_push () =
  let data = Bytes.of_string "\xde\xad\xbe\xef" in
  (* Direct push: opcode = length of data = 4 *)
  let instr = Script.Push_data { opcode = 0x04; data } in
  check_bool  "is push"     true (Script.is_push instr);
  check_int   "opcode_of"   0x04 (Script.opcode_of instr);
  check_bytes "data round-trip" data (Script.data_of instr)

let test_direct_push_single_byte () =
  let data = Bytes.make 1 '\xab' in
  let instr = Script.Push_data { opcode = 0x01; data } in
  check_int   "opcode 0x01"   0x01 (Script.opcode_of instr);
  check_bytes "1-byte data"   data (Script.data_of instr)

let test_direct_push_max () =
  (* Maximum direct push: opcode 0x4b = 75, data is 75 bytes. *)
  let data = Bytes.make 75 '\xff' in
  let instr = Script.Push_data { opcode = 0x4b; data } in
  check_int  "opcode 0x4b"    0x4b (Script.opcode_of instr);
  check_int  "data length 75" 75   (Bytes.length (Script.data_of instr))

(* ------------------------------------------------------------------ Push_data: OP_PUSHDATA1/2/4 *)

let test_pushdata1 () =
  (* OP_PUSHDATA1 (0x4c): data up to 255 bytes, length in 1 byte. *)
  let data = Bytes.make 100 '\xaa' in
  let instr = Script.Push_data { opcode = Script.op_pushdata1; data } in
  check_bool  "is push"       true  (Script.is_push instr);
  check_int   "opcode 0x4c"   0x4c  (Script.opcode_of instr);
  check_int   "data length"   100   (Bytes.length (Script.data_of instr))

let test_pushdata2 () =
  (* OP_PUSHDATA2 (0x4d): data up to 65535 bytes, length in 2 bytes LE. *)
  let data = Bytes.make 300 '\xbb' in
  let instr = Script.Push_data { opcode = Script.op_pushdata2; data } in
  check_int  "opcode 0x4d"    0x4d  (Script.opcode_of instr);
  check_int  "data length"    300   (Bytes.length (Script.data_of instr))

let test_pushdata4 () =
  (* OP_PUSHDATA4 (0x4e): data up to 2^32-1 bytes, length in 4 bytes LE. *)
  let data = Bytes.make 1024 '\xcc' in
  let instr = Script.Push_data { opcode = Script.op_pushdata4; data } in
  check_int  "opcode 0x4e"    0x4e  (Script.opcode_of instr);
  check_int  "data length"    1024  (Bytes.length (Script.data_of instr))

(* ------------------------------------------------------------------ Push_data: implicit-value opcodes *)

let test_op_1negate () =
  (* OP_1NEGATE (0x4f): pushes -1; data is empty in the representation. *)
  let instr = Script.Push_data { opcode = Script.op_1negate; data = Bytes.empty } in
  check_bool  "is push"     true  (Script.is_push instr);
  check_int   "opcode 0x4f" 0x4f  (Script.opcode_of instr);
  check_bytes "empty data"  Bytes.empty (Script.data_of instr)

let test_op_1_through_16 () =
  (* OP_1..OP_16 (0x51..0x60): push small integers; data is empty. *)
  for n = 0 to 15 do
    let op = Script.op_1 + n in
    let instr = Script.Push_data { opcode = op; data = Bytes.empty } in
    let got_op = Script.opcode_of instr in
    if got_op <> op then
      Alcotest.failf "OP_%d: opcode_of = 0x%02x, expected 0x%02x" (n+1) got_op op
  done

(* ------------------------------------------------------------------ empty push data *)

let test_empty_push_data () =
  (* A Push_data with Bytes.empty data is valid for OP_0 and implicit opcodes. *)
  let instr = Script.Push_data { opcode = Script.op_0; data = Bytes.empty } in
  check_bytes "empty data" Bytes.empty (Script.data_of instr);
  check_bool  "is push"    true (Script.is_push instr)

(* ------------------------------------------------------------------ arbitrary binary push data *)

let test_arbitrary_binary_data () =
  (* All byte values 0x00..0xFF survive round-trip through Push_data. *)
  let data = Bytes.init 256 Char.chr in
  let instr = Script.Push_data { opcode = Script.op_pushdata2; data } in
  let got = Script.data_of instr in
  check_bool "full byte range preserved" true (Bytes.equal data got)

(* ------------------------------------------------------------------ classification helpers *)

let test_is_direct_push () =
  check_bool "0x00 not direct push"  false (Script.is_direct_push 0x00);
  check_bool "0x01 is direct push"   true  (Script.is_direct_push 0x01);
  check_bool "0x4b is direct push"   true  (Script.is_direct_push 0x4b);
  check_bool "0x4c not direct push"  false (Script.is_direct_push 0x4c)

let test_direct_push_length () =
  check_int "length of 0x01" 1  (Script.direct_push_length 0x01);
  check_int "length of 0x20" 32 (Script.direct_push_length 0x20);
  check_int "length of 0x4b" 75 (Script.direct_push_length 0x4b)

let test_direct_push_length_invalid () =
  let raises opcode =
    try ignore (Script.direct_push_length opcode); false
    with Invalid_argument _ -> true
  in
  check_bool "0x00 raises" true (raises 0x00);
  check_bool "0x4c raises" true (raises 0x4c);
  check_bool "0xff raises" true (raises 0xff)

(* ------------------------------------------------------------------ equality *)

let test_equal_instruction_same () =
  let a = Script.Opcode 0xac in
  check_bool "reflexive" true (Script.equal_instruction a a)

let test_equal_instruction_different_variant () =
  let a = Script.Opcode 0x04 in
  let b = Script.Push_data { opcode = 0x04; data = Bytes.make 4 '\x00' } in
  check_bool "Opcode <> Push_data" false (Script.equal_instruction a b)

let test_equal_instruction_different_opcode () =
  let a = Script.Opcode 0xac in
  let b = Script.Opcode 0xae in
  check_bool "different opcodes" false (Script.equal_instruction a b)

let test_equal_instruction_different_data () =
  let a = Script.Push_data { opcode = 0x04; data = Bytes.make 4 '\x00' } in
  let b = Script.Push_data { opcode = 0x04; data = Bytes.make 4 '\x01' } in
  check_bool "different data" false (Script.equal_instruction a b)

let test_equal_script () =
  let s1 = [
    Script.Push_data { opcode = 0x14; data = Bytes.make 20 '\x42' };
    Script.Opcode Script.op_checksig;
  ] in
  let s2 = [
    Script.Push_data { opcode = 0x14; data = Bytes.make 20 '\x42' };
    Script.Opcode Script.op_checksig;
  ] in
  let s3 = [
    Script.Push_data { opcode = 0x14; data = Bytes.make 20 '\x00' };
    Script.Opcode Script.op_checksig;
  ] in
  check_bool "equal scripts"    true  (Script.equal s1 s2);
  check_bool "different data"   false (Script.equal s1 s3);
  check_bool "different length" false (Script.equal s1 [])

(* ------------------------------------------------------------------ opcode byte preserved *)

let test_opcode_preserved () =
  (* The wire opcode must be recoverable from every instruction. *)
  let instrs = [
    Script.Push_data { opcode = 0x00; data = Bytes.empty };  (* OP_0 *)
    Script.Push_data { opcode = 0x01; data = Bytes.make 1 '\xff' };
    Script.Push_data { opcode = 0x4c; data = Bytes.make 10 '\xaa' };
    Script.Opcode 0x76;  (* OP_DUP *)
    Script.Opcode 0xac;  (* OP_CHECKSIG *)
  ] in
  let expected_opcodes = [0x00; 0x01; 0x4c; 0x76; 0xac] in
  List.iter2 (fun instr expected ->
    let got = Script.opcode_of instr in
    if got <> expected then
      Alcotest.failf "opcode_of = 0x%02x, expected 0x%02x" got expected
  ) instrs expected_opcodes

(* ------------------------------------------------------------------ main *)

let () =
  Alcotest.run "script-types" [
    "empty", [
      "empty script",          `Quick, test_empty;
    ];
    "constants", [
      "opcode values",         `Quick, test_opcode_values;
    ];
    "Opcode", [
      "plain opcode",          `Quick, test_plain_opcode;
      "all 256 opcodes",       `Quick, test_arbitrary_opcode;
    ];
    "Push_data", [
      "OP_0",                  `Quick, test_op_0_push;
      "direct push 4 bytes",   `Quick, test_direct_push;
      "direct push 1 byte",    `Quick, test_direct_push_single_byte;
      "direct push max (75B)", `Quick, test_direct_push_max;
      "OP_PUSHDATA1",          `Quick, test_pushdata1;
      "OP_PUSHDATA2",          `Quick, test_pushdata2;
      "OP_PUSHDATA4",          `Quick, test_pushdata4;
      "OP_1NEGATE",            `Quick, test_op_1negate;
      "OP_1 through OP_16",    `Quick, test_op_1_through_16;
      "empty push data",       `Quick, test_empty_push_data;
      "arbitrary binary data", `Quick, test_arbitrary_binary_data;
    ];
    "classification", [
      "is_direct_push",        `Quick, test_is_direct_push;
      "direct_push_length",    `Quick, test_direct_push_length;
      "invalid length raises", `Quick, test_direct_push_length_invalid;
    ];
    "equality", [
      "reflexive",             `Quick, test_equal_instruction_same;
      "variant mismatch",      `Quick, test_equal_instruction_different_variant;
      "opcode mismatch",       `Quick, test_equal_instruction_different_opcode;
      "data mismatch",         `Quick, test_equal_instruction_different_data;
      "script equality",       `Quick, test_equal_script;
    ];
    "wire fidelity", [
      "opcode byte preserved", `Quick, test_opcode_preserved;
    ];
  ]

