(** SHA-256 and Bitcoin double-SHA-256 hash functions.

    All functions operate on [bytes] and return [bytes].
    The output is always 32 bytes (256 bits).

    No dependencies on Common, encoding, or any Bitcoin-specific module.
    This keeps the hash layer usable by every layer above it. *)

(** [sha256 data] computes SHA-256(data). Returns 32 bytes. *)
val sha256 : bytes -> bytes

(** [hash256 data] computes SHA-256(SHA-256(data)) — Bitcoin's standard
    double-hash used for transaction IDs, block IDs, and SIGHASH preimages.
    Returns 32 bytes. *)
val hash256 : bytes -> bytes

(** [sha256_string data] is [sha256] operating on a [string]. *)
val sha256_string : string -> bytes

(** [hash256_string data] is [hash256] operating on a [string]. *)
val hash256_string : string -> bytes
