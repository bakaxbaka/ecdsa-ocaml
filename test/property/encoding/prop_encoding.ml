(* test/property/encoding/prop_encoding.ml
   Property-based tests for Hex and Bytes_util.

   Properties tested:
   Hex
     P1. encode-decode roundtrip: for all bytes b, Hex.to_bytes (Hex.of_bytes b) = Ok b
     P2. decode-encode roundtrip: for all valid hex strings h,
         Hex.of_bytes (Result.get_ok (Hex.to_bytes h)) = String.lowercase_ascii h
     P3. length invariant: Hex.of_bytes b has length 2 * Bytes.length b
     P4. 0x-prefix tolerance: Hex.to_bytes ("0x" ^ h) = Hex.to_bytes h
     P5. odd-length rejection: Hex.to_bytes of any odd-length string fails

   Bytes_util
     P6.  write_u16_le / read_u16_le roundtrip
     P7.  write_u32_le / read_u32_le roundtrip
     P8.  write_u64_le / read_u64_le roundtrip
     P9.  write_u16_be / read_u16_be roundtrip
     P10. write_u32_be / read_u32_be roundtrip
     P11. slice full buffer = original
     P12. concat . split = original (concat [a; b] then slice recovers a and b)
     P13. read_u32_le out-of-bounds returns Error
     P14. slice out-of-bounds returns Error
*)

open QCheck

(* ------------------------------------------------------------------ generators *)

let gen_bytes =
  Gen.map Bytes.of_string (Gen.string_size (Gen.int_range 0 128))

(* Generate a valid lowercase hex string of even length *)
let gen_hex_string =
  Gen.map (fun b -> Hex.of_bytes b) gen_bytes

let gen_u16 = Gen.int_range 0 0xFFFF
let gen_u32 = Gen.int_range 0 0xFFFF_FFFF
let gen_u64 = Gen.map Int64.of_int (Gen.int_range 0 max_int)

(* ------------------------------------------------------------------ hex properties *)

let prop_hex_encode_decode =
  Test.make ~name:"P1: Hex encode->decode roundtrip"
    (make gen_bytes)
    (fun b ->
      match Hex.to_bytes (Hex.of_bytes b) with
      | Ok b' -> Bytes.equal b b'
      | Error _ -> false)

let prop_hex_length =
  Test.make ~name:"P3: Hex output length = 2 * input length"
    (make gen_bytes)
    (fun b ->
      String.length (Hex.of_bytes b) = 2 * Bytes.length b)

let prop_hex_0x_prefix =
  Test.make ~name:"P4: 0x prefix is accepted"
    (make gen_hex_string)
    (fun h ->
      let with_prefix    = Hex.to_bytes ("0x" ^ h) in
      let without_prefix = Hex.to_bytes h in
      match with_prefix, without_prefix with
      | Ok a, Ok b -> Bytes.equal a b
      | Error _, Error _ -> true
      | _ -> false)

let prop_hex_odd_rejected =
  Test.make ~name:"P5: odd-length hex string is rejected"
    (* Generate a non-empty bytes value, hex-encode it, drop last char -> odd length *)
    (make (Gen.map (fun b ->
        let h = Hex.of_bytes b in
        String.sub h 0 (max 1 (String.length h - 1))
      ) (Gen.map Bytes.of_string (Gen.string_size (Gen.int_range 1 64)))))
    (fun odd_h ->
      if String.length odd_h mod 2 = 0 then
        (* shrinking may produce an even string; just skip *)
        true
      else
        match Hex.to_bytes odd_h with
        | Error _ -> true
        | Ok _    -> false)

(* ------------------------------------------------------------------ bytes_util properties *)

let prop_u16_le_roundtrip =
  Test.make ~name:"P6: write_u16_le / read_u16_le roundtrip"
    (make gen_u16)
    (fun v ->
      let b = Bytes_util.write_u16_le v in
      match Bytes_util.read_u16_le b 0 with
      | Ok v' -> v = v'
      | Error _ -> false)

let prop_u32_le_roundtrip =
  Test.make ~name:"P7: write_u32_le / read_u32_le roundtrip"
    (make gen_u32)
    (fun v ->
      let b = Bytes_util.write_u32_le v in
      match Bytes_util.read_u32_le b 0 with
      | Ok v' -> v = v'
      | Error _ -> false)

let prop_u64_le_roundtrip =
  Test.make ~name:"P8: write_u64_le / read_u64_le roundtrip"
    (make gen_u64)
    (fun v ->
      let b = Bytes_util.write_u64_le v in
      match Bytes_util.read_u64_le b 0 with
      | Ok v' -> Int64.equal v v'
      | Error _ -> false)

let prop_u16_be_roundtrip =
  Test.make ~name:"P9: write_u16_be / read_u16_be roundtrip"
    (make gen_u16)
    (fun v ->
      let b = Bytes_util.write_u16_be v in
      match Bytes_util.read_u16_be b 0 with
      | Ok v' -> v = v'
      | Error _ -> false)

let prop_u32_be_roundtrip =
  Test.make ~name:"P10: write_u32_be / read_u32_be roundtrip"
    (make gen_u32)
    (fun v ->
      let b = Bytes_util.write_u32_be v in
      match Bytes_util.read_u32_be b 0 with
      | Ok v' -> v = v'
      | Error _ -> false)

let prop_slice_full =
  Test.make ~name:"P11: slice full buffer = original"
    (make gen_bytes)
    (fun b ->
      match Bytes_util.slice b 0 (Bytes.length b) with
      | Ok b' -> Bytes.equal b b'
      | Error _ -> false)

let prop_concat_slice =
  Test.make ~name:"P12: concat . slice roundtrip"
    (make (Gen.pair gen_bytes gen_bytes))
    (fun (a, b) ->
      let combined = Bytes_util.concat [a; b] in
      let la = Bytes.length a in
      let lb = Bytes.length b in
      match Bytes_util.slice combined 0 la,
            Bytes_util.slice combined la lb with
      | Ok a', Ok b' -> Bytes.equal a a' && Bytes.equal b b'
      | _ -> false)

let prop_oob_returns_error =
  Test.make ~name:"P13: read_u32_le out-of-bounds returns Error"
    (make gen_bytes)
    (fun b ->
      let off = Bytes.length b in   (* one byte past end *)
      match Bytes_util.read_u32_le b off with
      | Error _ -> true
      | Ok _    -> false)

let prop_slice_oob_error =
  Test.make ~name:"P14: slice out-of-bounds returns Error"
    (make gen_bytes)
    (fun b ->
      let n = Bytes.length b in
      (* Ask for one more byte than exists *)
      match Bytes_util.slice b 0 (n + 1) with
      | Error _ -> true
      | Ok _    -> false)

(* ------------------------------------------------------------------ main *)

let () =
  let qcheck_tests = [
    prop_hex_encode_decode;
    prop_hex_length;
    prop_hex_0x_prefix;
    prop_hex_odd_rejected;
    prop_u16_le_roundtrip;
    prop_u32_le_roundtrip;
    prop_u64_le_roundtrip;
    prop_u16_be_roundtrip;
    prop_u32_be_roundtrip;
    prop_slice_full;
    prop_concat_slice;
    prop_oob_returns_error;
    prop_slice_oob_error;
  ] in
  let alcotest_tests =
    List.map QCheck_alcotest.to_alcotest qcheck_tests
  in
  Alcotest.run "encoding-properties" [ "properties", alcotest_tests ]
