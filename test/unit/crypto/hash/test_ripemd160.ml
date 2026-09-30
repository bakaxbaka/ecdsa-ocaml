(* test/unit/crypto/hash/test_ripemd160.ml
   Known-vector tests for RIPEMD-160 and Hash160.

   This suite exists because the previous RIPEMD-160 implementation was wrong in
   a way that no existing test could see: it had no test at all.  Its rotation
   tables were fabricated and it raised, or returned a wrong digest, depending on
   input length.  A single empty-string vector would have caught that.

   The vectors below are the published RIPEMD-160 reference values from the
   original Dobbertin/Bosselaers/Preneel specification, plus the standard
   Bitcoin Hash160 relationship. *)

let hex_of_bytes b =
  let buf = Buffer.create (2 * Bytes.length b) in
  Bytes.iter (fun c -> Buffer.add_string buf (Printf.sprintf "%02x" (Char.code c))) b;
  Buffer.contents buf

let check_hash label expected input =
  let got = hex_of_bytes (Ripemd160.hash (Bytes.of_string input)) in
  Alcotest.(check string) label expected got

(* ------------------------------------------------------------------ vectors *)

let test_empty () =
  check_hash "ripemd160(\"\")" "9c1185a5c5e9fc54612808977ee8f548b2258d31" ""

let test_a () =
  check_hash "ripemd160(\"a\")" "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe" "a"

let test_abc () =
  check_hash "ripemd160(\"abc\")" "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc" "abc"

let test_message_digest () =
  check_hash "ripemd160(\"message digest\")"
    "5d0689ef49d2fae572b881b123a85ffa21595f36" "message digest"

let test_a_to_z () =
  check_hash "ripemd160(\"a..z\")"
    "f71c27109c692c1b56bbdceb5b9d2865b3708dbc" "abcdefghijklmnopqrstuvwxyz"

(* 8 x "1234567890" = 80 bytes: crosses the single-block boundary, which is the
   case where the broken implementation returned a wrong digest instead of
   raising. *)
let test_eight_blocks () =
  check_hash "ripemd160(8 x \"1234567890\")"
    "9b752e45573d4b39f4dbd3323cab82bf63326bfb"
    "12345678901234567890123456789012345678901234567890123456789012345678901234567890"

(* 56 bytes: the shortest input that needs a second padding block.  This value
   was produced by an independent implementation (Python hashlib / OpenSSL),
   NOT by this codebase — a constant copied from the code under test would make
   the assertion vacuous.  The same applies to every vector in this file. *)
let test_two_blocks () =
  check_hash "ripemd160(56 bytes)"
    "e72334b46c83cc70bef979e15453706c95b888be"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

(* ------------------------------------------------------------------ properties *)

let test_output_length () =
  List.iter
    (fun n ->
       let data = Bytes.make n 'x' in
       Alcotest.(check int) (Printf.sprintf "20 bytes for input length %d" n) 20
         (Bytes.length (Ripemd160.hash data)))
    [ 0; 1; 55; 56; 63; 64; 65; 127; 128; 1000 ]

let test_never_raises () =
  (* Exhaustive over lengths 0..200 so an invalid shift amount cannot hide. *)
  for n = 0 to 200 do
    let data = Bytes.make n 'Z' in
    let digest = Ripemd160.hash data in
    Alcotest.(check int) (Printf.sprintf "length %d" n) 20 (Bytes.length digest)
  done

let test_distinct_inputs_differ () =
  let a = Ripemd160.hash (Bytes.of_string "abc") in
  let b = Ripemd160.hash (Bytes.of_string "abd") in
  Alcotest.(check bool) "abc and abd differ" false (Bytes.equal a b)

(* ------------------------------------------------------------------ hash160 *)

(* Hash160(pubkey) = RIPEMD160(SHA256(pubkey)). The compressed generator point is
   the canonical vector: its Hash160 is the P2WPKH witness program of the
   address bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 (BIP173 test vector). *)
let test_hash160_generator () =
  let generator_compressed =
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
  in
  (* The literal above is ASCII; decode it to the 33 raw bytes of the SEC1 point
     before hashing, or the test would hash the text rather than the point. *)
  let n = String.length generator_compressed / 2 in
  let pk = Bytes.create n in
  for i = 0 to n - 1 do
    Bytes.set pk i
      (Char.chr (int_of_string ("0x" ^ String.sub generator_compressed (i * 2) 2)))
  done;
  let digest = Ripemd160.hash (Hash.sha256 pk) in
  Alcotest.(check string)
    "hash160(G) is the BIP173 P2WPKH witness program"
    "751e76e8199196d454941c45d1b3a323f1433bd6"
    (hex_of_bytes digest)

let test_hash160_bytes_interface () =
  Alcotest.(check int) "hash160 result is 20 bytes" 20
    (Bytes.length (Ripemd160.hash (Hash.sha256 (Bytes.of_string "test"))))

let () =
  Alcotest.run "ripemd160" [
    "known vectors", [
      "empty string",        `Quick, test_empty;
      "\"a\"",               `Quick, test_a;
      "\"abc\"",             `Quick, test_abc;
      "\"message digest\"",  `Quick, test_message_digest;
      "\"a..z\"",            `Quick, test_a_to_z;
      "8 x \"1234567890\"",  `Quick, test_eight_blocks;
      "56 bytes",            `Quick, test_two_blocks;
    ];
    "properties", [
      "output is 20 bytes",     `Quick, test_output_length;
      "never raises, len 0..200", `Quick, test_never_raises;
      "distinct inputs differ", `Quick, test_distinct_inputs_differ;
    ];
    "hash160", [
      "generator point",     `Quick, test_hash160_generator;
      "20-byte result",      `Quick, test_hash160_bytes_interface;
    ];
  ]
