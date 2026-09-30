(* lib/analysis/analysis.ml
   Top-level orchestration module for ECDSA signature analysis.

   Combines observation building, nonce analysis, and statistical
   aggregation into a unified pipeline for Bitcoin transaction analysis.
*)

(* ------------------------------------------------------------------ aliases *)

(** [analysis_signature] is a wrapped library, so its [Observation] module is
    only reachable as [Analysis_signature.Observation]; the rest of this file
    refers to it by the short name [Observation].  ([Statistics] and [Nonce]
    need no alias: their libraries are unwrapped, so those names are already
    top-level.) *)
module Observation = Analysis_signature.Observation

(* ------------------------------------------------------------------ types *)

type transaction_analysis = {
  txid : string;
  input_analyses : Nonce.input_analysis list;
  aggregate_stats : Statistics.aggregate_stats;
  critical_findings : string list;
}

type batch_analysis = {
  transactions : transaction_analysis list;
  total_critical : int;
  total_high : int;
  total_medium : int;
  summary : string;
}

(* ------------------------------------------------------------------ pipeline *)

(** [analyze_transaction tx txid spk_hints utxo_values]
    Runs the complete analysis pipeline on a single transaction:
    1. Build observations for each input
    2. Perform nonce analysis on observations
    3. Compute aggregate statistics
    4. Report critical findings
*)
let analyze_transaction
    (tx : Types.transaction)
    (txid : string)
    (spk_hints : bytes option list)
    (utxo_values : Int64.t option list) : transaction_analysis =

  (* Step 1: Build observations *)
  let observation_results = Observation.build_all tx txid spk_hints utxo_values in
  let observations = List.filter_map (fun (_, res) ->
    match res with
    | Ok obs -> Some obs
    | Error _ -> None
  ) observation_results in

  (* Step 2: Group observations by input for nonce analysis.
     [observations] already holds exactly the successfully built observations,
     so there is no need to re-filter [observation_results] here. *)
  let obs_by_input = observations in

  (* Step 3: Perform nonce analysis *)
  let input_analyses = Nonce.analyze_transaction txid [obs_by_input] in

  (* Step 4: Compute statistics *)
  let aggregate_stats = Statistics.compute_aggregate_stats [observations] in

  (* Step 5: Extract critical findings *)
  let critical_findings = ref [] in
  List.iter (fun analysis ->
    if analysis.Nonce.risk_level = "CRITICAL" then
      critical_findings := analysis.Nonce.summary :: !critical_findings;
    List.iter (fun attack ->
      match attack with
      | Nonce.Nonce_reuse { r; _ } ->
        critical_findings := Printf.sprintf "Nonce reuse (r=%s) detected"
          (Z.to_string r)
          :: !critical_findings
      | _ -> ()
    ) analysis.Nonce.attack_vectors
  ) input_analyses;

  {
    txid;
    input_analyses;
    aggregate_stats;
    critical_findings = !critical_findings;
  }

(** [analyze_transactions txs] analyzes multiple transactions *)
let analyze_transactions
    (txs : (Types.transaction * string * bytes option list * Int64.t option list) list)
    : batch_analysis =
  
  let transaction_analyses = List.map (fun (tx, txid, spk, values) ->
    analyze_transaction tx txid spk values
  ) txs in

  (* Count risk levels *)
  let critical = ref 0 in
  let high = ref 0 in
  let medium = ref 0 in

  List.iter (fun ta ->
    List.iter (fun ia ->
      match ia.Nonce.risk_level with
      | "CRITICAL" -> incr critical
      | "HIGH" -> incr high
      | "MEDIUM" -> incr medium
      | _ -> ()
    ) ta.input_analyses
  ) transaction_analyses;

  let summary =
    if !critical > 0 then
      Printf.sprintf "ALERT: %d critical vulnerabilities detected" !critical
    else if !high > 0 then
      Printf.sprintf "WARNING: %d high-risk issues found" !high
    else
      Printf.sprintf "Analyzed %d transactions - no critical issues" (List.length txs)
  in

  {
    transactions = transaction_analyses;
    total_critical = !critical;
    total_high = !high;
    total_medium = !medium;
    summary;
  }

(* ------------------------------------------------------------------ formatting *)

let format_input_analysis (ia : Nonce.input_analysis) : string =
  Printf.sprintf
    "Input %d [%s]:\n  Risk: %.2f (%s)\n  %s"
    ia.input_index ia.risk_level ia.risk_score ia.risk_level ia.summary

let format_transaction_analysis (ta : transaction_analysis) : string =
  let header = Printf.sprintf "=== Transaction %s ===\n" ta.txid in
  let inputs = String.concat "\n" (List.map format_input_analysis ta.input_analyses) in
  let findings =
    if List.length ta.critical_findings > 0 then
      Printf.sprintf "\n[CRITICAL FINDINGS]\n%s"
        (String.concat "\n" ta.critical_findings)
    else
      ""
  in
  header ^ inputs ^ findings

let format_batch_analysis (ba : batch_analysis) : string =
  let header = Printf.sprintf "=== Batch Analysis Results ===\n%s\n" ba.summary in
  let counts = Printf.sprintf
    "Risk Summary: %d critical, %d high, %d medium\n"
    ba.total_critical ba.total_high ba.total_medium
  in
  let tx_details = String.concat "\n\n" (List.map format_transaction_analysis ba.transactions) in
  header ^ counts ^ "\n" ^ tx_details

(* ------------------------------------------------------------------ export types *)

module Types = struct
  type t = transaction_analysis
  type batch = batch_analysis
end
