(** Statistical analysis of Bitcoin ECDSA signatures.

    Computes aggregate metrics across transaction observations:
    - Signature form distribution (low-S vs high-S)
    - Sighash type frequency
    - Message hash distribution
    - Public key recovery rates
    - Script type classification
    - ECDSA verification success rates
*)

(** Signature form statistics *)
type sig_form_stats = {
  low_s_count : int;
  high_s_count : int;
  low_s_ratio : float;
}

(** Sighash type distribution *)
type sighash_stats = {
  all_count : int;
  none_count : int;
  single_count : int;
  anyonecanpay_count : int;
  distribution : (int * int) list;
}

(** Message hash (z-value) statistics *)
type z_stats = {
  mean : float;
  variance : float;
  std_dev : float;
  min_value : Z.t;
  max_value : Z.t;
  range : Z.t;
  distribution_buckets : int array;
}

(** Public key statistics *)
type pubkey_stats = {
  compressed_count : int;
  uncompressed_count : int;
  recovery_failures : int;
  recovery_rate : float;
}

(** Script type distribution *)
type script_type_stats = {
  p2pkh_count : int;
  p2pk_count : int;
  p2wpkh_count : int;
  p2sh_count : int;
  p2wsh_count : int;
  p2tr_count : int;
  op_return_count : int;
  unknown_count : int;
}

(** ECDSA verification results *)
type ecdsa_stats = {
  verified_count : int;
  failed_count : int;
  verification_rate : float;
}

(** Aggregate statistics across all observations *)
type aggregate_stats = {
  total_inputs : int;
  total_signatures : int;
  sig_forms : sig_form_stats;
  sighash_types : sighash_stats;
  z_values : z_stats option;
  pubkeys : pubkey_stats;
  script_types : script_type_stats;
  ecdsa_verification : ecdsa_stats;
}

(** Compute aggregate statistics from observations *)
val compute_aggregate_stats :
  Analysis_signature.Observation.observation list list ->
  aggregate_stats

(** Format statistics for display *)
val format_stats : aggregate_stats -> string

(** Format z-value statistics *)
val format_z_stats : z_stats -> string

(** Export statistics as JSON *)
val stats_to_json : aggregate_stats -> string
