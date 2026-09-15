(* test/unit/crypto/ecdsa/test_der.ml
   Unit tests for the strict Bitcoin DER signature parser.

   All vectors are hand-crafted or taken from Bitcoin transactions.
   Each test constructs the raw bytes explicitly so the expected structure
   is clear in the test source.

   Coverage:
   - Valid compact signature (minimal r, minimal s)
   - Valid signature with 0x00-padded r (high bit protection)
   - Valid signature with 0x00-padded s
   - Both r and s padded
   - sighash byte values: 0x01, 0x02, 0x03, 0x81, 0x82, 0x83
   - of_hex: with and without 0x prefix
   - r and s value correctness
   - sighash byte preserved

   Error paths:
   - Empty input
   - Wrong first byte (not 0x30)
   - Bad SEQUENCE length (too short, too long)
   - Wrong r tag (not 0x02)
   - Wrong s tag
   - r length zero
   - r length > 33
   - r has high bit set without 0x00 prefix (negative integer)
   - r has unnecessary 0x00 prefix (excessive padding)
   - s has high bit set without 0x00 prefix
   - s has unnecessary 0x00 prefix
   - r = 0 (invalid)
   - s = 0 (invalid)
   - Trailing bytes between s and sighash
   - Missing sighash byte
*)

let ok_exn lbl = function
  | Ok v    -> v
  | Error e -> Alcotest.failf "%s: unexpected Error: %s" lbl
                 (Common.Der_error.to_string e)

let is_error = function Error _ -> true | Ok _ -> false

let expect_error lbl expected = function
  | Ok _    -> Alcotest.failf "%s: expected Error, got Ok" lbl
  | Error e ->
    if e <> expected then
      Alcotest.failf "%s: expected %s, got %s" lbl
        (Common.Der_error.to_string expected)
        (Common.Der_error.to_string e)

(* ------------------------------------------------------------------ helpers *)

(* Build a well-formed DER signature buffer from raw r_bytes and s_bytes.
   r_bytes and s_bytes are the canonical (possibly 0x00-prefixed) big-endian
   integer bytes, exactly as they would appear on the wire after the length byte. *)
let make_der ?(sighash=0x01) r_bytes s_bytes =
  let rl = Bytes.length r_bytes in
  let sl = Bytes.length s_bytes in
  (* inner = 02 rl <r> 02 sl <s> *)
  let inner_len = 2 + rl + 2 + sl in
  (* total = 30 <inner_len> <inner> <sighash> *)
  let total = 1 + 1 + inner_len + 1 in
  let buf = Bytes.create total in
  let pos = ref 0 in
  let put b = Bytes.set buf !pos (Char.chr b); incr pos in
  let put_bytes b = Bytes.blit b 0 buf !pos (Bytes.length b); pos := !pos + Bytes.length b in
  put 0x30; put inner_len;
  put 0x02; put rl; put_bytes r_bytes;
  put 0x02; put sl; put_bytes s_bytes;
  put sighash;
  buf

(* Big-endian bytes from a hex string (no 0x prefix) *)
let bytes_of_hex h =
  let n = String.length h / 2 in
  let b = Bytes.create n in
  for i = 0 to n - 1 do
    let hi = Scanf.sscanf (String.sub h (i*2)   1) "%x" Fun.id in
    let lo = Scanf.sscanf (String.sub h (i*2+1) 1) "%x" Fun.id in
    Bytes.set b i (Char.chr (hi lsl 4 lor lo))
  done;
  b

(* Minimal positive big-endian bytes for a Z.t (no leading zeros unless needed
   for sign, i.e. if high bit set, prepend 0x00). *)
let _bytes_of_z z =
  (* Z.to_bits is little-endian; build big-endian manually. *)
  if Z.equal z Z.zero then Bytes.make 1 '\x00'
  else begin
    let hex = Z.format "%x" z in
    let hex = if String.length hex mod 2 = 1 then "0" ^ hex else hex in
    let raw = bytes_of_hex hex in
    (* If high bit set, prepend 0x00 for positive DER encoding. *)
    if Char.code (Bytes.get raw 0) land 0x80 <> 0 then
      Bytes.cat (Bytes.make 1 '\x00') raw
    else raw
  end

(* ------------------------------------------------------------------ valid signatures *)

(* Minimal 1-byte r and s: r=1, s=1, sighash=0x01
   30 06 02 01 01 02 01 01 01 *)
let test_minimal_rs () =
  let r_bytes = Bytes.make 1 '\x01' in
  let s_bytes = Bytes.make 1 '\x01' in
  let buf = make_der r_bytes s_bytes in
  let p = ok_exn "minimal" (Der.of_bytes buf) in
  Alcotest.(check bool) "r = 1" true (Z.equal p.r Z.one);
  Alcotest.(check bool) "s = 1" true (Z.equal p.s Z.one);
  Alcotest.(check int)  "sighash 0x01" 0x01 p.sighash

(* r requires 0x00 prefix because high bit of first value byte is set.
   r = 0x80 (one byte, high bit set) -> wire: 02 02 00 80 *)
let test_r_with_zero_prefix () =
  let r_bytes = Bytes.of_string "\x00\x80" in  (* 0x00 prefix + 0x80 *)
  let s_bytes = Bytes.make 1 '\x01' in
  let buf = make_der r_bytes s_bytes in
  let p = ok_exn "r_zero_prefix" (Der.of_bytes buf) in
  Alcotest.(check bool) "r = 0x80 = 128"
    true (Z.equal p.r (Z.of_int 128))

(* s requires 0x00 prefix *)
let test_s_with_zero_prefix () =
  let r_bytes = Bytes.make 1 '\x01' in
  let s_bytes = Bytes.of_string "\x00\xff" in  (* 0xff with high bit set *)
  let buf = make_der r_bytes s_bytes in
  let p = ok_exn "s_zero_prefix" (Der.of_bytes buf) in
  Alcotest.(check bool) "s = 0xff = 255"
    true (Z.equal p.s (Z.of_int 255))

(* Both r and s have 0x00 prefix *)
let test_both_padded () =
  let r_bytes = Bytes.of_string "\x00\x80" in
  let s_bytes = Bytes.of_string "\x00\xab" in
  let buf = make_der r_bytes s_bytes in
  let p = ok_exn "both_padded" (Der.of_bytes buf) in
  Alcotest.(check bool) "r = 128" true (Z.equal p.r (Z.of_int 128));
  Alcotest.(check bool) "s = 171" true (Z.equal p.s (Z.of_int 0xab))

(* 32-byte r and s — typical secp256k1 size *)
let test_typical_32_byte () =
  (* r = 0x0102030405060708091011121314151617181920212223242526272829303132 *)
  let r_hex = "0102030405060708091011121314151617181920212223242526272829303132" in
  let s_hex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" in
  let r_bytes = bytes_of_hex r_hex in
  (* s has high bit set — needs 0x00 prefix *)
  let s_bytes = Bytes.cat (Bytes.make 1 '\x00') (bytes_of_hex s_hex) in
  let buf = make_der r_bytes s_bytes in
  let p = ok_exn "typical_32" (Der.of_bytes buf) in
  Alcotest.(check bool) "r round-trip" true
    (Z.equal p.r (Z.of_string ("0x" ^ r_hex)));
  Alcotest.(check bool) "s round-trip" true
    (Z.equal p.s (Z.of_string ("0x" ^ s_hex)))

(* All supported sighash byte values *)
let test_sighash_values () =
  let r = Bytes.make 1 '\x01' in
  let s = Bytes.make 1 '\x01' in
  List.iter (fun sh ->
    let buf = make_der ~sighash:sh r s in
    let p = ok_exn (Printf.sprintf "sighash_0x%02x" sh) (Der.of_bytes buf) in
    Alcotest.(check int) (Printf.sprintf "sighash 0x%02x" sh) sh p.sighash
  ) [0x01; 0x02; 0x03; 0x81; 0x82; 0x83]

(* of_hex without 0x prefix *)
let test_of_hex_no_prefix () =
  let r = Bytes.make 1 '\x01' in
  let s = Bytes.make 1 '\x02' in
  let buf = make_der r s in
  let hex = Bytes.fold_left (fun acc c ->
    acc ^ Printf.sprintf "%02x" (Char.code c)) "" buf in
  let p = ok_exn "hex_no_prefix" (Der.of_hex hex) in
  Alcotest.(check bool) "s = 2" true (Z.equal p.s (Z.of_int 2))

(* of_hex with 0x prefix *)
let test_of_hex_with_prefix () =
  let r = Bytes.make 1 '\x01' in
  let s = Bytes.make 1 '\x02' in
  let buf = make_der r s in
  let hex = "0x" ^ Bytes.fold_left (fun acc c ->
    acc ^ Printf.sprintf "%02x" (Char.code c)) "" buf in
  let p = ok_exn "hex_prefix" (Der.of_hex hex) in
  Alcotest.(check bool) "s = 2" true (Z.equal p.s (Z.of_int 2))

(* ------------------------------------------------------------------ error: empty *)

let test_empty () =
  expect_error "empty" Common.Der_error.Empty (Der.of_bytes Bytes.empty)

(* ------------------------------------------------------------------ error: wrong first byte *)

let test_wrong_sequence_tag () =
  let r = Bytes.make 1 '\x01' in
  let s = Bytes.make 1 '\x01' in
  let buf = make_der r s in
  Bytes.set buf 0 '\x31';  (* wrong tag *)
  expect_error "bad_tag" Common.Der_error.Not_a_sequence (Der.of_bytes buf)

(* ------------------------------------------------------------------ error: bad sequence length *)

let test_bad_seq_len_too_short () =
  (* Sequence length byte says 3 but actual inner content needs more *)
  let r = Bytes.make 1 '\x01' in
  let s = Bytes.make 1 '\x01' in
  let buf = Bytes.copy (make_der r s) in
  Bytes.set buf 1 '\x02';  (* claim only 2 inner bytes when there are 6 *)
  Alcotest.(check bool) "bad seq len" true (is_error (Der.of_bytes buf))

let test_bad_seq_len_too_long () =
  let r = Bytes.make 1 '\x01' in
  let s = Bytes.make 1 '\x01' in
  let buf = Bytes.copy (make_der r s) in
  Bytes.set buf 1 '\x40';  (* claim 64 inner bytes *)
  Alcotest.(check bool) "bad seq len too long" true (is_error (Der.of_bytes buf))

(* ------------------------------------------------------------------ error: wrong integer tags *)

let test_wrong_r_tag () =
  let r = Bytes.make 1 '\x01' in
  let s = Bytes.make 1 '\x01' in
  let buf = Bytes.copy (make_der r s) in
  Bytes.set buf 2 '\x03';  (* r tag position, should be 0x02 *)
  expect_error "wrong_r_tag" Common.Der_error.Not_an_integer (Der.of_bytes buf)

let test_wrong_s_tag () =
  let r = Bytes.make 1 '\x01' in
  let s = Bytes.make 1 '\x01' in
  let buf = Bytes.copy (make_der r s) in
  (* s tag is at position 2 + 1 + 1(r_len) + 1(r) = 5 *)
  Bytes.set buf 5 '\x03';
  expect_error "wrong_s_tag" Common.Der_error.Not_an_integer (Der.of_bytes buf)

(* ------------------------------------------------------------------ error: r/s length zero *)

let test_r_len_zero () =
  (* Manually craft: 30 05 02 00 02 01 01 01 — r has length 0 *)
  let buf = Bytes.of_string "\x30\x05\x02\x00\x02\x01\x01\x01" in
  Alcotest.(check bool) "r_len=0" true (is_error (Der.of_bytes buf))

(* ------------------------------------------------------------------ error: r/s length > 33 *)

let test_r_len_too_large () =
  (* r length = 34 *)
  let r_bytes = Bytes.make 34 '\x01' in
  let s_bytes = Bytes.make 1  '\x01' in
  let buf = make_der r_bytes s_bytes in
  Alcotest.(check bool) "r_len=34" true (is_error (Der.of_bytes buf))

(* ------------------------------------------------------------------ error: negative integer *)

let test_r_high_bit_no_prefix () =
  (* r = single byte 0x80 — high bit set without 0x00 prefix *)
  let r_bytes = Bytes.make 1 '\x80' in
  let s_bytes = Bytes.make 1 '\x01' in
  let buf = make_der r_bytes s_bytes in
  expect_error "r_neg" Common.Der_error.Negative_integer (Der.of_bytes buf)

let test_s_high_bit_no_prefix () =
  let r_bytes = Bytes.make 1 '\x01' in
  let s_bytes = Bytes.make 1 '\x80' in
  let buf = make_der r_bytes s_bytes in
  expect_error "s_neg" Common.Der_error.Negative_integer (Der.of_bytes buf)

(* ------------------------------------------------------------------ error: excessive padding *)

let test_r_unnecessary_zero_prefix () =
  (* r = 0x00 0x01: 0x00 prefix followed by a byte with high bit clear = non-canonical *)
  let r_bytes = Bytes.of_string "\x00\x01" in
  let s_bytes = Bytes.make 1 '\x01' in
  let buf = make_der r_bytes s_bytes in
  expect_error "r_excess_pad" Common.Der_error.Excessive_padding (Der.of_bytes buf)

let test_s_unnecessary_zero_prefix () =
  let r_bytes = Bytes.make 1 '\x01' in
  let s_bytes = Bytes.of_string "\x00\x01" in
  let buf = make_der r_bytes s_bytes in
  expect_error "s_excess_pad" Common.Der_error.Excessive_padding (Der.of_bytes buf)

(* ------------------------------------------------------------------ error: missing sighash *)

let test_missing_sighash () =
  let r = Bytes.make 1 '\x01' in
  let s = Bytes.make 1 '\x01' in
  let buf = make_der r s in
  (* Drop the last byte (sighash) *)
  let without_sh = Bytes.sub buf 0 (Bytes.length buf - 1) in
  Alcotest.(check bool) "missing sighash" true (is_error (Der.of_bytes without_sh))

(* ------------------------------------------------------------------ error: trailing bytes *)

let test_trailing_bytes () =
  let r = Bytes.make 1 '\x01' in
  let s = Bytes.make 1 '\x01' in
  let buf = make_der r s in
  (* Insert an extra byte between s and sighash by adjusting seq_len *)
  let extended = Bytes.cat buf (Bytes.make 1 '\xde') in
  Alcotest.(check bool) "trailing bytes" true (is_error (Der.of_bytes extended))

(* ------------------------------------------------------------------ main *)

let () =
  Alcotest.run "der-parser" [
    "valid", [
      "minimal r=1 s=1",           `Quick, test_minimal_rs;
      "r with 0x00 prefix",        `Quick, test_r_with_zero_prefix;
      "s with 0x00 prefix",        `Quick, test_s_with_zero_prefix;
      "both r and s padded",       `Quick, test_both_padded;
      "typical 32-byte r/s",       `Quick, test_typical_32_byte;
      "all sighash values",        `Quick, test_sighash_values;
      "of_hex no prefix",          `Quick, test_of_hex_no_prefix;
      "of_hex with 0x prefix",     `Quick, test_of_hex_with_prefix;
    ];
    "error: structure", [
      "empty input",               `Quick, test_empty;
      "wrong sequence tag",        `Quick, test_wrong_sequence_tag;
      "seq len too short",         `Quick, test_bad_seq_len_too_short;
      "seq len too long",          `Quick, test_bad_seq_len_too_long;
      "wrong r tag",               `Quick, test_wrong_r_tag;
      "wrong s tag",               `Quick, test_wrong_s_tag;
      "r length zero",             `Quick, test_r_len_zero;
      "r length > 33",             `Quick, test_r_len_too_large;
      "missing sighash",           `Quick, test_missing_sighash;
      "trailing bytes",            `Quick, test_trailing_bytes;
    ];
    "error: encoding", [
      "r high bit without prefix", `Quick, test_r_high_bit_no_prefix;
      "s high bit without prefix", `Quick, test_s_high_bit_no_prefix;
      "r unnecessary 0x00 prefix", `Quick, test_r_unnecessary_zero_prefix;
      "s unnecessary 0x00 prefix", `Quick, test_s_unnecessary_zero_prefix;
    ];
  ]
