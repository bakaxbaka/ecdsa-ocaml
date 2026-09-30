(** A signature observation suitable for cryptographic analysis.

    Only observations whose ECDSA verification succeeded should be passed to
    recovery routines.  [z] is the 256-bit Bitcoin signature hash interpreted
    as a non-negative integer. *)
type t = {
  txid : string;
  input_index : int;
  r : Z.t;
  s : Z.t;
  z : Z.t;
  pubkey : Curve.Point.t;
}

let make ~txid ~input_index ~r ~s ~z ~pubkey =
  if input_index < 0 then invalid_arg "Observation.make: negative input index";
  { txid; input_index; r; s; z; pubkey }
