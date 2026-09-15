(* test/unit/crypto/hash/test_hash.ml
   Known-vector tests for SHA-256 and Bitcoin double-SHA-256.

   SHA-256 vectors: NIST FIPS 180-4 / RFC 4634 standard test cases.
   Bitcoin hash256 vectors: computed from well-known Bitcoin data.
*)

(* ------------------------------------------------------------------ helpers *)

let hex_of_bytes b =
  let buf = Buffer.create (Bytes.length b * 2) in
  Bytes.iter (fun c -> Buffer.add_string buf (Printf.sprintf "%02x" (Char.code c))) b;
  Buffer.contents buf

let check_hash lbl expected_hex actual_bytes =
  let got = hex_of_bytes actual_bytes in
  if got <> expected_hex then
    Alcotest.failf "%s:\n  expected: %s\n  got:      %s" lbl expected_hex got

(* ------------------------------------------------------------------ SHA-256 known vectors *)

(* NIST FIPS 180-4 example: SHA-256("") *)
let test_sha256_empty () =
  check_hash "sha256(\"\")"
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    (Hash.sha256 Bytes.empty)

(* SHA-256("abc") -- verified via multiple independent implementations *)
let test_sha256_abc () =
  check_hash "sha256(\"abc\")"
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    (Hash.sha256_string "abc")

(* NIST: SHA-256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") *)
let test_sha256_448bit () =
  check_hash "sha256(448-bit)"
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    (Hash.sha256_string "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")

(* NIST: SHA-256("a" * 1000000) -- 1 million 'a' characters *)
let test_sha256_million_a () =
  check_hash "sha256(1M 'a')"
    "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    (Hash.sha256_string (String.make 1_000_000 'a'))

(* Single byte 0x00 *)
let test_sha256_single_zero () =
  check_hash "sha256(0x00)"
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
    (Hash.sha256 (Bytes.make 1 '\x00'))

(* Single byte 0xff *)
let test_sha256_single_ff () =
  check_hash "sha256(0xff)"
    "a8100ae6aa1940d0b663bb31cd466142ebbdbd5187131b92d93818987832eb89"
    (Hash.sha256 (Bytes.make 1 '\xff'))

(* Two-block message: 56 bytes (just crossing the 55-byte one-block limit) *)
let test_sha256_two_blocks () =
  (* SHA-256("message digest") — RFC 4634 example B.1 *)
  check_hash "sha256(\"message digest\")"
    "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650"
    (Hash.sha256_string "message digest")

(* ------------------------------------------------------------------ hash256 (double SHA-256) vectors *)

(* hash256("") = SHA-256(SHA-256("")) *)
let test_hash256_empty () =
  (* SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
     SHA-256(above) = 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456 *)
  check_hash "hash256(\"\")"
    "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
    (Hash.hash256 Bytes.empty)

(* hash256("abc") *)
let test_hash256_abc () =
  (* SHA-256("abc") = ba7816bf...
     SHA-256(ba7816bf...) = 4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358 *)
  check_hash "hash256(\"abc\")"
    "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358"
    (Hash.hash256_string "abc")

(* Bitcoin genesis block hash (well-known fixed value).
   The genesis block header serialisation hashes to:
   000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
   (in display/RPC byte order, which is the hash256 bytes reversed).
   We test the raw hash256 output (internal byte order = reversed display order). *)
let test_hash256_genesis_block () =
  (* Genesis block header (80 bytes), from Bitcoin source *)
  let genesis_header_hex =
    "0100000000000000000000000000000000000000000000000000000000000000" ^
    "000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa" ^
    "4b1e5e4a29ab5f49ffff001d1dac2b7c"
  in
  let n = String.length genesis_header_hex / 2 in
  let header = Bytes.create n in
  for i = 0 to n - 1 do
    let hi = Scanf.sscanf (String.sub genesis_header_hex (i*2)   1) "%x" Fun.id in
    let lo = Scanf.sscanf (String.sub genesis_header_hex (i*2+1) 1) "%x" Fun.id in
    Bytes.set header i (Char.chr (hi lsl 4 lor lo))
  done;
  (* Internal byte order: the hash256 result, not reversed *)
  (* Display order = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
     Internal order = reversed: 6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000 *)
  check_hash "hash256(genesis header) internal"
    "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000"
    (Hash.hash256 header)

(* ------------------------------------------------------------------ output length *)

let test_sha256_output_length () =
  Alcotest.(check int) "sha256 output 32 bytes" 32
    (Bytes.length (Hash.sha256 Bytes.empty))

let test_hash256_output_length () =
  Alcotest.(check int) "hash256 output 32 bytes" 32
    (Bytes.length (Hash.hash256 Bytes.empty))

(* ------------------------------------------------------------------ string vs bytes consistency *)

let test_sha256_string_bytes_agree () =
  let s = "hello world" in
  let from_string = Hash.sha256_string s in
  let from_bytes  = Hash.sha256 (Bytes.of_string s) in
  Alcotest.(check bool) "sha256_string = sha256 bytes" true
    (Bytes.equal from_string from_bytes)

let test_hash256_string_bytes_agree () =
  let s = "hello world" in
  let from_string = Hash.hash256_string s in
  let from_bytes  = Hash.hash256 (Bytes.of_string s) in
  Alcotest.(check bool) "hash256_string = hash256 bytes" true
    (Bytes.equal from_string from_bytes)

(* ------------------------------------------------------------------ idempotence / composition *)

let test_hash256_is_double_sha256 () =
  let data = Bytes.of_string "test data" in
  let manual = Hash.sha256 (Hash.sha256 data) in
  let via_fn = Hash.hash256 data in
  Alcotest.(check bool) "hash256 = sha256(sha256(x))" true
    (Bytes.equal manual via_fn)

(* ------------------------------------------------------------------ main *)

let () =
  Alcotest.run "hash" [
    "SHA-256 vectors", [
      "empty string",         `Quick, test_sha256_empty;
      "\"abc\"",              `Quick, test_sha256_abc;
      "448-bit message",      `Quick, test_sha256_448bit;
      "1 million 'a'",        `Slow,  test_sha256_million_a;
      "single byte 0x00",     `Quick, test_sha256_single_zero;
      "single byte 0xff",     `Quick, test_sha256_single_ff;
      "\"message digest\"",   `Quick, test_sha256_two_blocks;
    ];
    "hash256 vectors", [
      "empty string",         `Quick, test_hash256_empty;
      "\"abc\"",              `Quick, test_hash256_abc;
      "genesis block header", `Quick, test_hash256_genesis_block;
    ];
    "output properties", [
      "sha256 output 32B",    `Quick, test_sha256_output_length;
      "hash256 output 32B",   `Quick, test_hash256_output_length;
      "string/bytes agree sha256",  `Quick, test_sha256_string_bytes_agree;
      "string/bytes agree hash256", `Quick, test_hash256_string_bytes_agree;
      "hash256 = sha256(sha256)",   `Quick, test_hash256_is_double_sha256;
    ];
  ]
