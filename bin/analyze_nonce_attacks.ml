(*
  bin/analyze_nonce_attacks.ml
  
  Bitcoin ECDSA Nonce Attack Detection Tool
  
  Reads Bitcoin transactions from JSON (or raw hex), builds ECDSA observations,
  performs nonce relationship analysis, and reports detected vulnerabilities.
  
  Usage:
    dune exec bin/analyze_nonce_attacks.exe -- <json_file>
    dune exec bin/analyze_nonce_attacks.exe -- --tx <hex> [--tx <hex> ...]
    dune exec bin/analyze_nonce_attacks.exe -- --help
    
  Examples:
    # Analyze fetched transactions from JSON file
    dune exec bin/analyze_nonce_attacks.exe -- 1L12SQ3DC448GWtSiBkiExqyhWEXk1pHEB.json
    
    # Analyze single transaction by hex
    dune exec bin/analyze_nonce_attacks.exe -- --tx d33ade0feef46c87...
    
    # Analyze multiple transactions
    dune exec bin/analyze_nonce_attacks.exe -- --tx <hex1> --tx <hex2> --tx <hex3>
*)

open Printf

(* ================================================================ JSON parsing *)

(** Parse transaction hex from command line or file *)
let parse_json_file (path : string) : string list =
  try
    let ic = open_in path in
    let content = really_input_string ic (in_channel_length ic) in
    close_in ic;
    
    (* Simple JSON extraction: find all "tx_hash" fields *)
    let open Str in
    let pattern = Str.regexp "\"tx_hash\":\\s*\"\\([a-f0-9]+\\)\"" in
    let txids = ref [] in
    try
      ignore (Str.search_forward pattern content 0);
      while true do
        let txid = Str.matched_group 1 content in
        txids := txid :: !txids;
        ignore (Str.search_forward pattern content (Str.match_end ()))
      done;
      !txids
    with Not_found ->
      List.rev !txids
  with _ ->
    printf "Error: Could not read JSON file: %s\n" path;
    []

(* ================================================================ Transaction parsing *)

let parse_hex_transaction (hex : string) : Types.transaction option =
  try
    match Tx_parser.of_hex hex with
    | Ok tx -> Some tx
    | Error _ -> None
  with _ -> None

(* ================================================================ Analysis *)

type analysis_result = {
  tx_hash : string;
  tx : Types.transaction option;
  analysis : Analysis.transaction_analysis option;
  error : string option;
}

let analyze_transaction_hex (hex : string) : analysis_result =
  let tx_hash = String.sub hex 0 (min 16 (String.length hex)) in
  match parse_hex_transaction hex with
  | None ->
    {
      tx_hash;
      tx = None;
      analysis = None;
      error = Some "Failed to parse transaction";
    }
  | Some tx ->
    try
      let analysis = Analysis.analyze_transaction tx tx_hash [] [] in
      {
        tx_hash;
        tx = Some tx;
        analysis = Some analysis;
        error = None;
      }
    with e ->
      {
        tx_hash;
        tx = Some tx;
        analysis = None;
        error = Some (Printexc.to_string e);
      }

(* ================================================================ Formatting *)

let format_result (r : analysis_result) : string =
  match r.analysis with
  | Some analysis ->
    Analysis.format_transaction_analysis analysis
  | None ->
    match r.error with
    | Some err ->
      sprintf "=== Transaction %s ===\nError: %s\n" r.tx_hash err
    | None ->
      sprintf "=== Transaction %s ===\nNo analysis available\n" r.tx_hash

let print_summary (results : analysis_result list) : unit =
  let total = List.length results in
  let parsed = List.length (List.filter (fun r -> r.tx <> None) results) in
  let analyzed = List.length (List.filter (fun r -> r.analysis <> None) results) in
  let errors = List.length (List.filter (fun r -> r.error <> None) results) in
  
  printf "\n=== SUMMARY ===\n";
  printf "Transactions: %d\n" total;
  printf "Parsed: %d\n" parsed;
  printf "Analyzed: %d\n" analyzed;
  printf "Errors: %d\n" errors;
  
  (* Count critical findings *)
  let critical_count = ref 0 in
  let high_count = ref 0 in
  List.iter (fun r ->
    match r.analysis with
    | Some analysis ->
      List.iter (fun ia ->
        match ia.Nonce.risk_level with
        | "CRITICAL" -> incr critical_count
        | "HIGH" -> incr high_count
        | _ -> ()
      ) analysis.input_analyses
    | None -> ()
  ) results;
  
  if !critical_count > 0 then
    printf "\n[ALERT] %d CRITICAL vulnerabilities detected!\n" !critical_count;
  if !high_count > 0 then
    printf "[WARNING] %d HIGH-risk issues found\n" !high_count

(* ================================================================ Main *)

let print_help () =
  printf "Bitcoin ECDSA Nonce Attack Detection Tool\n";
  printf "\n";
  printf "Usage:\n";
  printf "  analyze_nonce_attacks <json_file>           - Analyze transactions from JSON file\n";
  printf "  analyze_nonce_attacks --tx <hex> [--tx ...] - Analyze individual transactions\n";
  printf "  analyze_nonce_attacks --help                - Show this help message\n";
  printf "\n";
  printf "Examples:\n";
  printf "  analyze_nonce_attacks 1L12SQ3DC448GWtSiBkiExqyhWEXk1pHEB.json\n";
  printf "  analyze_nonce_attacks --tx d33ade0feef46c87...\n";
  printf "\n"

let () =
  let args = Array.to_list Sys.argv in
  let cmd_args = match args with _ :: rest -> rest | [] -> [] in
  
  if List.length cmd_args = 0 then (
    print_help ();
    exit 1
  );
  
  let txs = ref [] in
  
  (* Parse command line arguments *)
  let rec parse_args = function
    | [] -> ()
    | "--help" :: rest -> print_help (); parse_args rest
    | "--tx" :: hex :: rest -> txs := hex :: !txs; parse_args rest
    | "--tx" :: _rest -> printf "Error: --tx requires an argument\n"; exit 1
    | json_file :: rest when not (String.starts_with ~prefix:"--" json_file) ->
      (* Assume it's a JSON file *)
      let fetched_txs = parse_json_file json_file in
      txs := List.rev_append fetched_txs !txs;
      parse_args rest
    | arg :: rest ->
      printf "Unknown argument: %s\n" arg;
      parse_args rest
  in
  
  parse_args cmd_args;
  
  if List.length !txs = 0 then (
    printf "Error: No transactions specified\n";
    print_help ();
    exit 1
  );
  
  printf "Analyzing %d transactions for nonce vulnerabilities...\n\n" (List.length !txs);
  
  (* Analyze each transaction *)
  let results = List.map analyze_transaction_hex !txs in
  
  (* Print results *)
  List.iter (fun r ->
    printf "%s\n" (format_result r)
  ) results;
  
  (* Print summary *)
  print_summary results
