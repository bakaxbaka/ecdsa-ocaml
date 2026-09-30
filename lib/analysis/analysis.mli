(** Unified ECDSA signature analysis pipeline.

    Orchestrates the complete analysis workflow:
    1. Observation building (transaction parsing, signature extraction, sighash computation)
    2. Nonce relationship detection (reuse, HNP, lattice attacks)
    3. Statistical aggregation (distribution analysis, verification rates)
    4. Critical finding extraction and reporting

    {1 Example}

    {[
      let tx = Parser.of_hex raw_hex |> Result.get_ok in
      let analysis = Analysis.analyze_transaction tx "txid" [] [] in
      Printf.printf "%s\n" (Analysis.format_transaction_analysis analysis);
      Printf.printf "Critical: %d\n" (List.length analysis.critical_findings)
    ]}
*)

(** Result of analyzing a single transaction *)
type transaction_analysis = {
  txid : string;
  input_analyses : Nonce.input_analysis list;
  aggregate_stats : Statistics.aggregate_stats;
  critical_findings : string list;
}

(** Result of analyzing a batch of transactions *)
type batch_analysis = {
  transactions : transaction_analysis list;
  total_critical : int;
  total_high : int;
  total_medium : int;
  summary : string;
}

(** Analyze a single transaction with full pipeline *)
val analyze_transaction :
  Types.transaction ->
  string ->
  bytes option list ->
  Int64.t option list ->
  transaction_analysis

(** Analyze multiple transactions *)
val analyze_transactions :
  (Types.transaction * string * bytes option list * Int64.t option list) list ->
  batch_analysis

(** Format transaction analysis for display *)
val format_transaction_analysis : transaction_analysis -> string

(** Format batch analysis for display *)
val format_batch_analysis : batch_analysis -> string

(** Export types *)
module Types : sig
  type t = transaction_analysis
  type batch = batch_analysis
end
