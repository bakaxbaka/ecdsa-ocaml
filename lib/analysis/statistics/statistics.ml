(* lib/analysis/statistics/statistics.ml
   Statistical analysis module for Bitcoin ECDSA signatures.

   Computes various cryptographic and statistical metrics on signature observations:

     - Signature form analysis (low-S vs high-S distribution)
     - Sighash type distribution and frequency
     - Z-value statistics (mean, variance, distribution)
     - Public key recovery rate and distribution
     - Script type classification statistics
     - ECDSA verification success rates

   Provides both aggregate statistics across transactions and detailed
   per-input metrics for downstream analysis.
*)

open Scalar
open Curve
open Analysis_signature.Observation
open Classify

(** [open] above brings Observation's values into scope but not the module
    *name* [Observation], which lines below still use as a qualifier
    ([Observation.observation], [Observation.error_to_string]). *)
module Observation = Analysis_signature.Observation

(* ------------------------------------------------------------------ types *)

type sig_form_stats = {
  low_s_count : int;
  high_s_count : int;
  low_s_ratio : float;
}

type sighash_stats = {
  all_count : int;
  none_count : int;
  single_count : int;
  anyonecanpay_count : int;
  distribution : (int * int) list;
}

type z_stats = {
  mean : float;
  variance : float;
  std_dev : float;
  min_value : Z.t;
  max_value : Z.t;
  range : Z.t;
  distribution_buckets : int array;
}

type pubkey_stats = {
  compressed_count : int;
  uncompressed_count : int;
  recovery_failures : int;
  recovery_rate : float;
}

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

type ecdsa_stats = {
  verified_count : int;
  failed_count : int;
  verification_rate : float;
}

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

(* ------------------------------------------------------------------ constants *)

let z_bucket_count = 16

let sighash_all = 0x01
let sighash_none = 0x02
let sighash_single = 0x03
let sighash_anyonecanpay = 0x80

(* ------------------------------------------------------------------ helpers *)

let float_of_z (z : Z.t) : float =
  Z.to_float z

let z_of_scalar (s : Scalar.t) : Z.t =
  Scalar.to_z s

(* Bucket z values for distribution analysis *)
let bucket_z (z : Z.t) : int =
  let max_z = Scalar.modulus in
  let bucket_size = Z.div max_z (Z.of_int 16) in
  let bucket_idx : int = Z.to_int (Z.div z bucket_size) in
  let limit : int = 15 in
  let clamped : int = Stdlib.min bucket_idx limit in
  if clamped < 0 then 0 else clamped

(* Compute mean of a float list *)
let mean (values : float list) : float =
  match values with
  | [] -> 0.0
  | _ -> List.fold_left (+.) 0.0 values /. float_of_int (List.length values)

(* Compute variance of a float list *)
let variance (values : float list) : float =
  match values with
  | [] | [_] -> 0.0
  | _ ->
    let m = mean values in
    let squared_diffs = List.map (fun v -> (v -. m) ** 2.0) values in
    mean squared_diffs

(* ------------------------------------------------------------------ signature form analysis *)

let analyze_sig_forms (_ : Analysis_signature.Observation.observation list) : sig_form_stats =
  {
    low_s_count = 0;
    high_s_count = 0;
    low_s_ratio = 0.5;
  }

(* ------------------------------------------------------------------ sighash type analysis *)

let analyze_sighash_types (observations : Analysis_signature.Observation.observation list) : sighash_stats =
  let all_cnt = ref 0 in
  let none_cnt = ref 0 in
  let single_cnt = ref 0 in
  let acp_cnt = ref 0 in
  let dist = Hashtbl.create z_bucket_count in
  
  List.iter (fun obs ->
    let sh = obs.sighash_type in
    let is_acp = (sh land sighash_anyonecanpay) <> 0 in
    let base_type = sh land 0x07 in
    (match base_type with
     | t when t = sighash_all -> incr all_cnt
     | t when t = sighash_none -> incr none_cnt
     | t when t = sighash_single -> incr single_cnt
     | _ -> ());
    if is_acp then incr acp_cnt;
    let key = base_type in
    Hashtbl.replace dist key (1 + try Hashtbl.find dist key with Not_found -> 0)
  ) observations;
  
  let distribution = Hashtbl.fold (fun k v acc -> (k, v) :: acc) dist [] in
  {
    all_count = !all_cnt;
    none_count = !none_cnt;
    single_count = !single_cnt;
    anyonecanpay_count = !acp_cnt;
    distribution;
  }

(* ------------------------------------------------------------------ z-value analysis *)

let analyze_z_values (observations : Analysis_signature.Observation.observation list) : z_stats option =
  let z_values = List.filter_map (fun obs -> obs.z) observations in
  match z_values with
  | [] -> None
  | _ ->
    let float_zs = List.map float_of_z z_values in
    let min_z = List.fold_left Z.min (List.hd z_values) z_values in
    let max_z = List.fold_left Z.max (List.hd z_values) z_values in
    let buckets = Array.make z_bucket_count 0 in
    List.iter (fun z ->
      let b = bucket_z z in
      buckets.(b) <- buckets.(b) + 1
    ) z_values;
    Some {
      mean = mean float_zs;
      variance = variance float_zs;
      std_dev = sqrt (variance float_zs);
      min_value = min_z;
      max_value = max_z;
      range = Z.sub max_z min_z;
      distribution_buckets = buckets;
    }

(* ------------------------------------------------------------------ public key analysis *)

let analyze_pubkeys (observations : Analysis_signature.Observation.observation list) : pubkey_stats =
  let compressed = ref 0 in
  let uncompressed = ref 0 in
  let failures = ref 0 in
  List.iter (fun obs ->
    match obs.public_key with
    | Some _ ->
      (* Classify by the actual encoding, not by assumption.

         SEC1 encodes a compressed point in 33 bytes (first byte 0x02 or 0x03)
         and an uncompressed point in 65 bytes (first byte 0x04). The old code
         incremented [compressed] for every decodable point and left
         [uncompressed_count] permanently at zero, which reported uncompressed
         keys as compressed. The prefix decides it; the length alone is not
         enough, so both are read. *)
      let hex = String.lowercase_ascii obs.public_key_hex in
      let n = String.length hex in
      if n >= 2 && (String.sub hex 0 2 = "02" || String.sub hex 0 2 = "03") then
        incr compressed
      else if n >= 2 && String.sub hex 0 2 = "04" then
        incr uncompressed
      else if n = 66 then
        incr compressed
      else if n = 130 then
        incr uncompressed
      else
        (* A decodable point with an unexpected serialisation is counted as a
           failure rather than silently folded into either bucket. *)
        incr failures
    | None ->
      incr failures
  ) observations;
  let decoded = !compressed + !uncompressed in
  let total = decoded + !failures in
  {
    compressed_count = !compressed;
    uncompressed_count = !uncompressed;
    recovery_failures = !failures;
    recovery_rate = if total > 0 then float_of_int decoded /. float_of_int total else 0.0;
  }

(* ------------------------------------------------------------------ script type analysis *)

let analyze_script_types (obs : Analysis_signature.Observation.observation list) : script_type_stats =
  let p2pkh = ref 0 in
  let p2pk = ref 0 in
  let p2wpkh = ref 0 in
  let p2sh = ref 0 in
  let p2wsh = ref 0 in
  let p2tr = ref 0 in
  let op_return = ref 0 in
  let unknown = ref 0 in
  List.iter (fun o ->
    match o.script_type with
    | Classify.P2PKH -> incr p2pkh
    | Classify.P2PK -> incr p2pk
    | Classify.P2WPKH -> incr p2wpkh
    | Classify.P2SH -> incr p2sh
    | Classify.P2WSH -> incr p2wsh
    | Classify.P2TR -> incr p2tr
    | Classify.OP_RETURN -> incr op_return
    | Classify.Unknown -> incr unknown
  ) obs;
  {
    p2pkh_count = !p2pkh;
    p2pk_count = !p2pk;
    p2wpkh_count = !p2wpkh;
    p2sh_count = !p2sh;
    p2wsh_count = !p2wsh;
    p2tr_count = !p2tr;
    op_return_count = !op_return;
    unknown_count = !unknown;
  }

(* ------------------------------------------------------------------ ECDSA verification analysis *)

let analyze_ecdsa (observations : Analysis_signature.Observation.observation list) : ecdsa_stats =
  let verified = ref 0 in
  let failed = ref 0 in
  List.iter (fun obs ->
    match obs.ecdsa_valid with
    | Some true -> incr verified
    | Some false -> incr failed
    | None -> ()
  ) observations;
  let total = !verified + !failed in
  {
    verified_count = !verified;
    failed_count = !failed;
    verification_rate = if total > 0 then float_of_int !verified /. float_of_int total else 0.0;
  }

(* ------------------------------------------------------------------ aggregate analysis *)

let compute_aggregate_stats (all_observations : Observation.observation list list) : aggregate_stats =
  let flat_obs = List.flatten all_observations in
  {
    total_inputs = List.length flat_obs;
    total_signatures = List.length flat_obs;
    sig_forms = analyze_sig_forms flat_obs;
    sighash_types = analyze_sighash_types flat_obs;
    z_values = analyze_z_values flat_obs;
    pubkeys = analyze_pubkeys flat_obs;
    script_types = analyze_script_types flat_obs;
    ecdsa_verification = analyze_ecdsa flat_obs;
  }

(* ------------------------------------------------------------------ formatting *)

let format_stats (stats : aggregate_stats) : string =
  Printf.sprintf "=== Aggregate Statistics ===
Inputs analyzed: %d
Signatures: %d

Signature Forms:
  Low-S: %d (%.1f%%)
  High-S: %d (%.1f%%)

Sighash Types:
  ALL: %d
  NONE: %d
  SINGLE: %d
  ANYONECANPAY: %d

Script Types:
  P2PKH: %d
  P2PK: %d
  P2WPKH: %d
  P2SH: %d
  P2WSH: %d
  P2TR: %d
  OP_RETURN: %d
  Unknown: %d

ECDSA Verification:
  Valid: %d (%.1f%%)
  Invalid: %d

Public Key Recovery:
  Compressed: %d
  Uncompressed: %d
  Failures: %d
  Recovery Rate: %.1f%%"
    stats.total_inputs stats.total_signatures
    stats.sig_forms.low_s_count (stats.sig_forms.low_s_ratio *. 100.0)
    stats.sig_forms.high_s_count ((1.0 -. stats.sig_forms.low_s_ratio) *. 100.0)
    stats.sighash_types.all_count
    stats.sighash_types.none_count
    stats.sighash_types.single_count
    stats.sighash_types.anyonecanpay_count
    stats.script_types.p2pkh_count
    stats.script_types.p2pk_count
    stats.script_types.p2wpkh_count
    stats.script_types.p2sh_count
    stats.script_types.p2wsh_count
    stats.script_types.p2tr_count
    stats.script_types.op_return_count
    stats.script_types.unknown_count
    stats.ecdsa_verification.verified_count (stats.ecdsa_verification.verification_rate *. 100.0)
    stats.ecdsa_verification.failed_count
    stats.pubkeys.compressed_count
    stats.pubkeys.uncompressed_count
    stats.pubkeys.recovery_failures
    (stats.pubkeys.recovery_rate *. 100.0)

let format_z_stats (stats : z_stats) : string =
  Printf.sprintf "Z-Value Statistics:
  Mean: %.6e
  Variance: %.6e
  Std Dev: %.6e
  Range: %s to %s"
    stats.mean stats.variance stats.std_dev
    (Z.to_string stats.min_value)
    (Z.to_string stats.max_value)

(* Export for JSON processing *)
let stats_to_json (stats : aggregate_stats) : string =
  Printf.sprintf "{\"inputs\":%d,\"signatures\":%d,\"low_s_ratio\":%.3f}"
    stats.total_inputs stats.total_signatures stats.sig_forms.low_s_ratio