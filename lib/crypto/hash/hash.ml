(* lib/crypto/hash/hash.ml
   SHA-256 and Bitcoin double-SHA-256 via digestif. *)

(* digestif.SHA256 context API:
     Digestif.SHA256.digest_bytes : bytes -> Digestif.SHA256.t
     Digestif.SHA256.to_raw_string : Digestif.SHA256.t -> string *)

let sha256 (data : bytes) : bytes =
  let digest = Digestif.SHA256.digest_bytes data in
  Bytes.of_string (Digestif.SHA256.to_raw_string digest)

let hash256 (data : bytes) : bytes =
  sha256 (sha256 data)

let sha256_string (data : string) : bytes =
  sha256 (Bytes.of_string data)

let hash256_string (data : string) : bytes =
  hash256 (Bytes.of_string data)
