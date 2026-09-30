(** Module for analyzing Bitcoin transactions and extracting nonce data. *)

type transaction = {
  hash : string;
  nonce : int;
  timestamp : int;
}

(** Parses a transaction hex string into a transaction record. *)
val parse_transaction : string -> (transaction * string, Common.Parse_error.t) result
