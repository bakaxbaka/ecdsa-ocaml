(* lib/crypto/hash/ripemd160.ml
   RIPEMD-160.

   This delegates to digestif rather than carrying a hand-written compression
   function.  The previous implementation here was incorrect in a way that was
   invisible without test vectors:

     - its rotation tables were fabricated (a monotonic 11..76 sequence rather
       than the published RIPEMD-160 constants, whose left path begins
       11 14 15 12 5 8 7 9 ...), so `rotl 76 x` evaluated `x lsr -44`;
     - the message word-order permutations were absent, and every round read the
       same words in the same order;
     - the five round constants were absent;
     - `f1` was defined as the function RIPEMD-160 calls `f3`.

   The observable result was a raise or a wrong digest depending on input length,
   while a glance at the file suggested a complete implementation.  Since
   digestif is already a dependency of this library, and since
   `Analysis_signature.Observation.hash160` was already using digestif's RMD160
   directly, the two hash160 paths in this tree disagreed with each other.  This
   removes the disagreement by making the primitive a thin, correct wrapper.

   The type is [bytes -> bytes] and the digest is 20 bytes, matching the
   published interface in ripemd160.mli. *)

let hash (data : bytes) : bytes =
  Digestif.RMD160.(digest_bytes data |> to_raw_string |> Bytes.of_string)
