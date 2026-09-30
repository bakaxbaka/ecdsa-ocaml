open Transaction_analysis

type state = {
  recent_nonces : (int * int) list ref;
}

let create_state () = 
  { recent_nonces = ref [] }

let is_repeated_nonce state tx =
  let nonces : (int * int) list = Stdlib.(!) state.recent_nonces in
  List.exists (fun (n, _) -> n = tx.nonce) nonces

(* [recent_nonces] is a [(nonce, timestamp)] list; [state] is a record, so the
   dereference is unambiguous here. *)
let update_recent_nonces state tx =
  let now = 1609459200 in (* Simulated current time *)
  let window = 3600 in (* 1 hour window *)
  let existing : (int * int) list = Stdlib.(!) state.recent_nonces in
  let filtered = List.filter (fun (_, ts) -> ts > now - window) existing in
  state.recent_nonces := (tx.nonce, tx.timestamp) :: filtered
