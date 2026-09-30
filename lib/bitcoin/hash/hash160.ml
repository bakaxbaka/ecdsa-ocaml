(* lib/bitcoin/hash/hash160.ml
   Implementation of Hash160: RIPEMD160(SHA256(data)). *)

let hash160 data =
  let sha256_hash = Hash.sha256 data in
  Ripemd160.hash sha256_hash
