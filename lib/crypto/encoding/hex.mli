(** Hexadecimal encoding and decoding.

    All functions treat hex strings as lowercase by default.
    Input decoding is case-insensitive.
    An optional "0x" prefix is accepted on input and never emitted on output. *)

(** [of_bytes b] encodes [b] as a lowercase hex string, no prefix. *)
val of_bytes : bytes -> string

(** [of_string s] encodes the raw bytes of [s] as a lowercase hex string. *)
val of_string : string -> string

(** [to_bytes h] decodes a hex string [h] to bytes.
    Accepts an optional leading "0x" prefix.
    Returns [Error] if the string contains non-hex characters or has odd length. *)
val to_bytes : string -> (bytes, Common.Parse_error.t) result

(** [to_string h] is [to_bytes h] with the result mapped to [string]. *)
val to_string : string -> (string, Common.Parse_error.t) result

(** [pp_bytes b] is [of_bytes b] — a convenience alias for printing. *)
val pp_bytes : bytes -> string
