(* test/unit/crypto/encoding/test_encoding.ml
   Unit tests with known vectors for Hex and Bytes_util. *)

let () = Random.self_init ()

(* ------------------------------------------------------------------ helpers *)

let ok_exn = function Ok v -> v | Error _ -> failwith "unexpected Error"
let is_error = function Error _ -> true | Ok _ -> false

(* ------------------------------------------------------------------ Hex vectors *)

module Hex_tests = struct
  let test_empty () =
    Alcotest.(check string) "empty bytes -> empty hex"
      "" (Hex.of_bytes Bytes.empty);
    Alcotest.(check bool) "empty hex -> empty bytes"
      true (Hex.to_bytes "" = Ok Bytes.empty)

  let test_single_byte () =
    Alcotest.(check string) "0x00" "00" (Hex.of_bytes (Bytes.make 1 '\x00'));
    Alcotest.(check string) "0xff" "ff" (Hex.of_bytes (Bytes.make 1 '\xff'));
    Alcotest.(check string) "0xab" "ab" (Hex.of_bytes (Bytes.make 1 '\xab'))

  let test_known_vectors () =
    let vectors = [
      ("deadbeef",     "\xde\xad\xbe\xef");
      ("0102030405",   "\x01\x02\x03\x04\x05");
      ("00ff80",       "\x00\xff\x80");
      ("",             "");
    ] in
    List.iter (fun (hex, raw) ->
      let msg = Printf.sprintf "decode %s" hex in
      Alcotest.(check string) msg
        raw (Bytes.to_string (ok_exn (Hex.to_bytes hex)));
      Alcotest.(check string) (Printf.sprintf "encode %s" hex)
        hex (Hex.of_bytes (Bytes.of_string raw))
    ) vectors

  let test_0x_prefix () =
    let a = ok_exn (Hex.to_bytes "deadbeef") in
    let b = ok_exn (Hex.to_bytes "0xdeadbeef") in
    let c = ok_exn (Hex.to_bytes "0XDEADBEEF") in
    Alcotest.(check bool) "0x prefix stripped" true (Bytes.equal a b);
    Alcotest.(check bool) "0X prefix stripped" true (Bytes.equal a c)

  let test_case_insensitive () =
    let lo = ok_exn (Hex.to_bytes "abcdef") in
    let hi = ok_exn (Hex.to_bytes "ABCDEF") in
    Alcotest.(check bool) "case insensitive" true (Bytes.equal lo hi)

  let test_odd_length_rejected () =
    Alcotest.(check bool) "odd length rejected" true (is_error (Hex.to_bytes "abc"))

  let test_invalid_chars_rejected () =
    Alcotest.(check bool) "invalid char rejected" true (is_error (Hex.to_bytes "gg"));
    Alcotest.(check bool) "space rejected"        true (is_error (Hex.to_bytes "ab cd"))

  let tests = [
    "empty",                  `Quick, test_empty;
    "single byte",            `Quick, test_single_byte;
    "known vectors",          `Quick, test_known_vectors;
    "0x prefix",              `Quick, test_0x_prefix;
    "case insensitive",       `Quick, test_case_insensitive;
    "odd length rejected",    `Quick, test_odd_length_rejected;
    "invalid chars rejected", `Quick, test_invalid_chars_rejected;
  ]
end

(* ------------------------------------------------------------------ Bytes_util vectors *)

module Bu_tests = struct
  let test_u16_le () =
    (* 0x0102 in LE is [0x02; 0x01] *)
    let b = Bytes_util.write_u16_le 0x0102 in
    Alcotest.(check char) "LE byte 0" '\x02' (Bytes.get b 0);
    Alcotest.(check char) "LE byte 1" '\x01' (Bytes.get b 1);
    Alcotest.(check int) "read back" 0x0102 (ok_exn (Bytes_util.read_u16_le b 0))

  let test_u32_le () =
    let b = Bytes_util.write_u32_le 0xDEADBEEF in
    Alcotest.(check char) "LE[0]" '\xEF' (Bytes.get b 0);
    Alcotest.(check char) "LE[1]" '\xBE' (Bytes.get b 1);
    Alcotest.(check char) "LE[2]" '\xAD' (Bytes.get b 2);
    Alcotest.(check char) "LE[3]" '\xDE' (Bytes.get b 3);
    Alcotest.(check int) "read back" 0xDEADBEEF (ok_exn (Bytes_util.read_u32_le b 0))

  let test_u64_le () =
    let v = 0x0102030405060708L in
    let b = Bytes_util.write_u64_le v in
    Alcotest.(check char) "LE64[0]" '\x08' (Bytes.get b 0);
    Alcotest.(check char) "LE64[7]" '\x01' (Bytes.get b 7);
    Alcotest.(check int64) "read back" v (ok_exn (Bytes_util.read_u64_le b 0))

  let test_u16_be () =
    let b = Bytes_util.write_u16_be 0x0102 in
    Alcotest.(check char) "BE[0]" '\x01' (Bytes.get b 0);
    Alcotest.(check char) "BE[1]" '\x02' (Bytes.get b 1);
    Alcotest.(check int) "read back" 0x0102 (ok_exn (Bytes_util.read_u16_be b 0))

  let test_u32_be () =
    let b = Bytes_util.write_u32_be 0xDEADBEEF in
    Alcotest.(check char) "BE[0]" '\xDE' (Bytes.get b 0);
    Alcotest.(check char) "BE[3]" '\xEF' (Bytes.get b 3);
    Alcotest.(check int) "read back" 0xDEADBEEF (ok_exn (Bytes_util.read_u32_be b 0))

  let test_slice () =
    let b = Bytes.of_string "\x01\x02\x03\x04\x05" in
    let s = ok_exn (Bytes_util.slice b 1 3) in
    Alcotest.(check string) "slice [1,3)"
      "\x02\x03\x04" (Bytes.to_string s)

  let test_slice_oob () =
    let b = Bytes.of_string "\x01\x02" in
    Alcotest.(check bool) "slice past end" true
      (is_error (Bytes_util.slice b 0 3));
    Alcotest.(check bool) "slice negative off" true
      (is_error (Bytes_util.slice b (-1) 1))

  let test_concat () =
    let a = Bytes.of_string "hello" in
    let b = Bytes.of_string " world" in
    let c = Bytes_util.concat [a; b] in
    Alcotest.(check string) "concat" "hello world" (Bytes.to_string c)

  let test_read_oob () =
    let b = Bytes.of_string "\x01\x02\x03" in
    Alcotest.(check bool) "u32 oob" true (is_error (Bytes_util.read_u32_le b 0));
    Alcotest.(check bool) "u16 exact fit" false
      (is_error (Bytes_util.read_u16_le b 1))   (* bytes [1..2] = valid *)

  let test_zero_values () =
    Alcotest.(check int) "u16_le zero" 0
      (ok_exn (Bytes_util.read_u16_le (Bytes_util.write_u16_le 0) 0));
    Alcotest.(check int) "u32_le zero" 0
      (ok_exn (Bytes_util.read_u32_le (Bytes_util.write_u32_le 0) 0));
    Alcotest.(check int64) "u64_le zero" 0L
      (ok_exn (Bytes_util.read_u64_le (Bytes_util.write_u64_le 0L) 0))

  let test_max_values () =
    Alcotest.(check int) "u16_le max" 0xFFFF
      (ok_exn (Bytes_util.read_u16_le (Bytes_util.write_u16_le 0xFFFF) 0));
    Alcotest.(check int) "u32_le max" 0xFFFF_FFFF
      (ok_exn (Bytes_util.read_u32_le (Bytes_util.write_u32_le 0xFFFF_FFFF) 0))

  (* Bitcoin transaction output values are unsigned 64-bit (satoshis).
     Max supply = 2_099_999_997_690_000 sat < Int64.max_int = 9_223_372_036_854_775_807.
     Verify that values with high bits set in each 32-bit half survive the
     Int32 intermediate stage without sign-extension corruption. *)
  let test_u64_high_bit_halves () =
    (* High bit of low half set: 0x0000_0000_8000_0000L *)
    let v1 = 0x0000_0000_8000_0000L in
    Alcotest.(check int64) "u64 high bit low half" v1
      (ok_exn (Bytes_util.read_u64_le (Bytes_util.write_u64_le v1) 0));
    (* High bit of high half set: 0x8000_0000_0000_0000L (negative as Int64) *)
    let v2 = Int64.min_int in (* 0x8000_0000_0000_0000L *)
    Alcotest.(check int64) "u64 Int64.min_int roundtrip" v2
      (ok_exn (Bytes_util.read_u64_le (Bytes_util.write_u64_le v2) 0));
    (* Max Bitcoin value: 21_000_000 BTC in satoshis *)
    let max_btc_sat = Int64.of_string "2100000000000000" in
    Alcotest.(check int64) "u64 max bitcoin supply" max_btc_sat
      (ok_exn (Bytes_util.read_u64_le (Bytes_util.write_u64_le max_btc_sat) 0))

  let tests = [
    "u16 little-endian",   `Quick, test_u16_le;
    "u32 little-endian",   `Quick, test_u32_le;
    "u64 little-endian",   `Quick, test_u64_le;
    "u16 big-endian",      `Quick, test_u16_be;
    "u32 big-endian",      `Quick, test_u32_be;
    "slice",               `Quick, test_slice;
    "slice oob",           `Quick, test_slice_oob;
    "concat",              `Quick, test_concat;
    "read oob",            `Quick, test_read_oob;
    "zero values",         `Quick, test_zero_values;
    "max values",          `Quick, test_max_values;
    "u64 high-bit halves", `Quick, test_u64_high_bit_halves;
  ]
end

(* ------------------------------------------------------------------ main *)

let () =
  Alcotest.run "encoding-unit" [
    "Hex",        Hex_tests.tests;
    "Bytes_util", Bu_tests.tests;
  ]
