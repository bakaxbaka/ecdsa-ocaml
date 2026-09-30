(* test/unit/api/test_json.ml
   Tests for lib/api/json.ml — the JSON layer the console depends on.

   This suite exists because lib/api had no tests at all despite being the newest
   code in the tree, and because one of its functions is a trap: [z_of_bytes_be]
   exists precisely because Stdlib's [Z.of_bits] reads LITTLE-endian. Using the
   stdlib function on a Bitcoin hash silently reverses the value while still
   producing a plausible number, so a test pins the endianness down explicitly.

   Also covered: escape round-tripping, the no-truncation guarantee on
   serialisation, and the Z.t dual decimal/hex encoding that keeps JavaScript from
   losing precision. *)

(* ------------------------------------------------------------------ endianness *)

(* The load-bearing test in this file. A big-endian byte string must be read
   most-significant-byte first. If this ever regresses to Z.of_bits, every hash
   in the API silently reverses. *)
let test_z_of_bytes_be_single () =
  Alcotest.(check string) "0x01 -> 1" "1" (Z.to_string (Json.z_of_bytes_be (Bytes.of_string "\x01")))

let test_z_of_bytes_be_two () =
  (* 0x01 0x00 is 256 big-endian; little-endian would give 1. *)
  Alcotest.(check string) "0x0100 -> 256" "256"
    (Z.to_string (Json.z_of_bytes_be (Bytes.of_string "\x01\x00")))

let test_z_of_bytes_be_matches_stdlib_reverse () =
  let b = Bytes.of_string "\xde\xad\xbe\xef" in
  let be = Json.z_of_bytes_be b in
  (* Z.of_bits is little-endian; reversing the bytes first must agree with ours. *)
  let rev = Bytes.create 4 in
  for i = 0 to 3 do Bytes.set rev i (Bytes.get b (3 - i)) done;
  Alcotest.(check string) "big-endian == little-endian of reversed"
    (Z.to_string (Z.of_bits (Bytes.to_string rev)))
    (Z.to_string be)

let test_z_of_bytes_be_hash () =
  (* A 32-byte hash. 0x80 as the first byte makes the value exceed 2^255, which
     also proves no signed interpretation crept in. *)
  let h = Bytes.make 32 '\x00' in
  Bytes.set h 0 '\x80';
  let v = Json.z_of_bytes_be h in
  Alcotest.(check int) "high bit does not go negative" 1 (Z.sign v);
  Alcotest.(check int) "32 bytes of 0x80.. = 2^255" 256 (Z.numbits v)

let test_z_of_bytes_be_empty () =
  Alcotest.(check string) "empty -> 0" "0"
    (Z.to_string (Json.z_of_bytes_be Bytes.empty))

(* ------------------------------------------------------------------ Z.t encoding *)

let test_z_dual_representation () =
  let v = Z.of_string "0xdeadbeef" in
  match Json.z v with
  | Json.Obj fields ->
    let dec = List.assoc "dec" fields and hex = List.assoc "hex" fields in
    Alcotest.(check string) "decimal exact" "3735928559"
      (match dec with Json.Str s -> s | _ -> "<not a string>");
    Alcotest.(check int) "hex is zero-padded to 64 chars" 64
      (match hex with Json.Str s -> String.length s | _ -> 0)
  | _ -> Alcotest.fail "Json.z must produce an object with dec and hex"

(* A value beyond JavaScript's 2^53 must survive as an exact decimal string. *)
let test_z_beyond_double_precision () =
  let v = Z.sub (Z.pow (Z.of_int 2) 200) Z.one in
  match Json.z v with
  | Json.Obj fields ->
    (match List.assoc "dec" fields with
     | Json.Str s ->
       Alcotest.(check bool) "exceeds 2^53" true (String.length s > 16);
       Alcotest.(check string) "round-trips exactly" (Z.to_string v) s
     | _ -> Alcotest.fail "dec must be a string")
  | _ -> Alcotest.fail "expected object"

let test_z_negative_hex () =
  match Json.z (Z.of_int (-255)) with
  | Json.Obj fields ->
    (match List.assoc "hex" fields with
     | Json.Str s -> Alcotest.(check bool) "negative keeps its sign" true (String.length s > 0 && s.[0] = '-')
     | _ -> Alcotest.fail "hex must be a string")
  | _ -> Alcotest.fail "expected object"

let test_bytes_states_length () =
  match Json.bytes (Bytes.of_string "abc") with
  | Json.Obj fields ->
    (match List.assoc "hex" fields, List.assoc "len" fields with
     | Json.Str h, Json.Int n ->
       Alcotest.(check string) "hex" "616263" h;
       Alcotest.(check int) "len reported" 3 n
     | _ -> Alcotest.fail "expected hex string and int len")
  | _ -> Alcotest.fail "expected object"

(* ------------------------------------------------------------------ escaping *)

(* Every case is a single string; the escaping cases are separate literals.
   (An earlier revision of this test wrote these without commas, so OCaml parsed
   the whole block as one giant tuple. Worth the comment.) *)
let test_string_escaping_round_trip () =
  let cases = [
    "plain";
    "with \"quotes\"";
    "back\\slash";
    "new\nline";
    "tab\there";
    "carriage\rreturn";
    "control \x01 char";
    "unicode: \xc3\xa9\xc3\xa8";
    "";
  ] in
  List.iter
    (fun s ->
       let json = Json.to_string (Json.Str s) in
       match Json.parse json with
       | Ok (Json.Str back) -> Alcotest.(check string) (Printf.sprintf "round-trip %S" s) s back
       | Ok _ -> Alcotest.failf "%S parsed as a non-string" s
       | Error e -> Alcotest.failf "%S failed to parse back: %s" s e)
    cases

let test_no_truncation_on_serialisation () =
  (* The contract: serialisation never shortens a value. A 100k-character string
     must come back byte-for-byte complete. *)
  let big = String.make 100_000 'x' in
  let json = Json.to_string (Json.Str big) in
  match Json.parse json with
  | Ok (Json.Str back) -> Alcotest.(check int) "length preserved exactly" 100_000 (String.length back)
  | _ -> Alcotest.fail "large string did not round-trip"

let test_large_list_complete () =
  let n = 20_000 in
  let items = List.init n (fun i -> Json.Int i) in
  match Json.parse (Json.to_string (Json.List items)) with
  | Ok (Json.List back) -> Alcotest.(check int) "every element present" n (List.length back)
  | _ -> Alcotest.fail "large list did not round-trip"

(* ------------------------------------------------------------------ structures *)

let test_object_round_trip () =
  let v = Json.Obj [
    "s", Json.Str "x";
    "i", Json.Int 42;
    "b", Json.Bool true;
    "n", Json.Null;
    "l", Json.List [Json.Int 1; Json.Int 2];
    "o", Json.Obj ["inner", Json.Str "y"];
  ] in
  match Json.parse (Json.to_string v) with
  | Ok parsed ->
    Alcotest.(check string) "re-serialises identically" (Json.to_string v) (Json.to_string parsed)
  | Error e -> Alcotest.failf "nested object failed: %s" e

let test_member_and_accessors () =
  let v = Json.Obj ["hex", Json.Str "ab"; "n", Json.Int 3] in
  Alcotest.(check (option string)) "member string" (Some "ab")
    (match Json.member "hex" v with Some s -> Json.as_string s | None -> None);
  Alcotest.(check (option int)) "member int" (Some 3)
    (match Json.member "n" v with Some s -> Json.as_int s | None -> None);
  Alcotest.(check bool) "absent is None" true (Json.member "nope" v = None)

let test_null_is_not_a_number () =
  (* NaN and infinity are not valid JSON. They must serialise to null rather
     than to a token a client would misread as a number. *)
  Alcotest.(check string) "NaN -> null" "null" (Json.to_string (Json.Float Float.nan));
  Alcotest.(check string) "inf -> null" "null" (Json.to_string (Json.Float Float.infinity))

let test_float_rendering () =
  Alcotest.(check string) "integer float keeps .0" "1.0" (Json.to_string (Json.Float 1.0));
  Alcotest.(check string) "fraction" "0.5" (Json.to_string (Json.Float 0.5))

(* ------------------------------------------------------------------ parse errors *)

let test_parse_rejects_bad_input () =
  let bad = ["{"; "[1,"; "\"unterminated"; "{\"a\":}"; "tru"; "{}extra"] in
  List.iter
    (fun s ->
       match Json.parse s with
       | Error _ -> ()
       | Ok _ -> Alcotest.failf "%S should not have parsed" s)
    bad

let test_parse_escapes () =
  let cases = [
    "{\"a\":\"\\u00e9\"}";
    "{\"a\":\"\\n\"}";
    "{\"a\":\"\\t\"}";
    "{\"a\":\"\\\\\"}";
    "{\"a\":1e10}";
    "{\"a\":-0.5}";
    "  {  \"a\"  :  \"b\"  }  ";
  ] in
  List.iter
    (fun s ->
       match Json.parse s with
       | Ok _ -> ()
       | Error e -> Alcotest.failf "%S should have parsed: %s" s e)
    cases

let () =
  Alcotest.run "api-json" [
    "endianness", [
      "single byte",            `Quick, test_z_of_bytes_be_single;
      "two bytes",              `Quick, test_z_of_bytes_be_two;
      "agrees with Z.of_bits on reversed", `Quick, test_z_of_bytes_be_matches_stdlib_reverse;
      "hash high bit stays positive", `Quick, test_z_of_bytes_be_hash;
      "empty",                  `Quick, test_z_of_bytes_be_empty;
    ];
    "z encoding", [
      "dual decimal/hex",       `Quick, test_z_dual_representation;
      "beyond 2^53 exact",      `Quick, test_z_beyond_double_precision;
      "negative sign",          `Quick, test_z_negative_hex;
      "bytes carries length",   `Quick, test_bytes_states_length;
    ];
    "escaping", [
      "round-trip all cases",   `Quick, test_string_escaping_round_trip;
      "100k string complete",   `Quick, test_no_truncation_on_serialisation;
      "20k list complete",      `Quick, test_large_list_complete;
    ];
    "structures", [
      "nested round-trip",      `Quick, test_object_round_trip;
      "member accessors",       `Quick, test_member_and_accessors;
      "NaN/inf become null",    `Quick, test_null_is_not_a_number;
      "float rendering",        `Quick, test_float_rendering;
    ];
    "parser", [
      "rejects malformed",      `Quick, test_parse_rejects_bad_input;
      "accepts escapes",        `Quick, test_parse_escapes;
    ];
  ]
