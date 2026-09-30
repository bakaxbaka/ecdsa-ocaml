(** Module for detecting repeated nonces in a stream of transactions. *)

open Transaction_analysis

(** State for the nonce checker, tracking nonces and their timestamps. *)
type state = {
  recent_nonces : (int * int) list ref;
}

val create_state : unit -> state
val is_repeated_nonce : state -> transaction -> bool
val update_recent_nonces : state -> transaction -> unit
