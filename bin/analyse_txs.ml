(*
  bin/analyse_txs.ml
  Bitcoin ECDSA Transaction Analysis Tool

  Analyzes three Bitcoin transactions to extract and verify ECDSA signatures,
  compute z values, and detect cryptographic relationships.

  Usage: dune exec -- bin/analyse_txs.exe <tx1_hex> <tx2_hex> <tx3_hex>
  
  Each transaction can be:
    - Raw hex transaction (will be parsed)
    - Path to file containing hex data

  Output:
    - Full observation records for each input
    - Cryptographic statistics across all inputs
    - Nonce relationship analysis
    - Risk assessment for each transaction
*)

(* Parse transactions using Tx_parser wrapper to avoid Parser namespace collision *)
let parse_tx_hex h = Tx_parser.of_hex h

open Analysis_signature.Observation

(* ------------------------------------------------------------------ command line *)

let print_usage () =
  print_endline "Bitcoin ECDSA Transaction Analysis Tool";
  print_endline "";
  print_endline "Usage: analyse_txs <tx1> <tx2> <tx3>";
  print_endline "";
  print_endline "Each transaction can be:";
  print_endline "  - Raw hex string (complete transaction)";
  print_endline "  - Txid (will be fetched from blockchain.info)";
  print_endline "  - File path (will be read as hex)";
  print_endline "";
  print_endline "Examples:";
  print_endline "  analyse_txs d33ade0f1234... ef95039c5678... 2427823cabcd...";
  print_endline "  analyse_txs /path/to/tx1.hex /path/to/tx2.hex /path/to/tx3.hex"

(* ------------------------------------------------------------------ transaction fetching *)

let is_hex_string (s : string) : bool =
  String.length s >= 64 &&
  String.for_all (fun c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) s

let is_txid_format (s : string) : bool =
  String.length s = 64 &&
  is_hex_string s

let is_file_path (s : string) : bool =
  Sys.file_exists s

let fetch_transaction (input : string) : string =
  if is_file_path input then (
    print_endline ("Reading from file " ^ input ^ "...");
    let ic = open_in input in
    let content = really_input_string ic (in_channel_length ic) in
    close_in ic;
    String.trim content
  )
  else if is_hex_string input then (
    print_endline "Using raw hex transaction";
    input
  )
  else if is_txid_format input then (
    print_endline ("Txid format detected: " ^ input);
    print_endline "Note: Automatic blockchain.info fetching not available in this build.";
    print_endline "Please provide raw transaction hex or a file path instead.";
    exit 1
  )
  else (
    Printf.eprintf "Invalid transaction format: %s\n" input;
    exit 1
  )

(* ------------------------------------------------------------------ hex utilities *)

let hex_of_bytes (b : bytes) : string =
  let hex_chars = "0123456789abcdef" in
  let result = Bytes.create (2 * Bytes.length b) in
  for i = 0 to Bytes.length b - 1 do
    let byte = int_of_char (Bytes.get b i) in
    Bytes.set result (2 * i) hex_chars.[byte lsr 4];
    Bytes.set result (2 * i + 1) hex_chars.[byte land 0x0F];
  done;
  Bytes.to_string result

let bytes_of_hex (h : string) : bytes =
  let len = String.length h / 2 in
  let result = Bytes.create len in
  for i = 0 to len - 1 do
    let hi = int_of_char h.[2 * i] in
    let lo = int_of_char h.[2 * i + 1] in
    let hi_val = if hi >= 97 then hi - 87 else if hi >= 65 then hi - 55 else hi - 48 in
    let lo_val = if lo >= 97 then lo - 87 else if lo >= 65 then lo - 55 else lo - 48 in
    Bytes.set result i (Char.chr ((hi_val lsl 4) lor lo_val));
  done;
  result

(* ------------------------------------------------------------------ main analysis *)

let analyze_transactions (tx1 : string) (tx2 : string) (tx3 : string) : unit =
  print_endline "";
  print_endline "=================================================";
  print_endline "  Bitcoin ECDSA Transaction Analysis";
  print_endline "=================================================";
  print_endline "";
  
  (* Parse transactions *)
  let raw_txs = [
    ("TX1", fetch_transaction tx1);
    ("TX2", fetch_transaction tx2);
    ("TX3", fetch_transaction tx3);
  ] in
  
  let transactions = List.map (fun (name, hex) ->
    print_endline ("Parsing " ^ name ^ "...");
    match parse_tx_hex hex with
    | Ok tx -> (name, tx)
    | Error e ->
      Printf.eprintf "Error parsing %s: %s\n" name (Common.Parse_error.to_string e);
      exit 1
  ) raw_txs in
  
  (* Extract observations for each transaction *)
  let observations_per_tx = List.map (fun (name, tx) ->
    print_endline ("Extracting signatures from " ^ name ^ "...");
    let txid = Hex.of_bytes (Bytes.of_string name) in
    let results = Analysis_signature.Observation.build_all tx txid [] [] in
    let obs_list = List.filter_map (fun (_, result) ->
      match result with
      | Ok obs -> Some obs
      | Error e ->
        Printf.eprintf "Error building observation: %s\n" (Analysis_signature.Observation.error_to_string e);
        None
    ) results in
    (name, obs_list)
  ) transactions in
  
  (* Compute aggregate statistics *)
  let all_obs = List.map snd observations_per_tx |> List.flatten in
  if all_obs <> [] then (
    print_endline "";
    print_endline "=================================================";
    print_endline "  Aggregate Statistics";
    print_endline "=================================================";
    print_endline "";
    
    let stats = Statistics.compute_aggregate_stats [all_obs] in
    print_endline (Statistics.format_stats stats);
    
    match stats.Statistics.z_values with
    | Some z_stats ->
      print_endline "";
      print_endline (Statistics.format_z_stats z_stats)
    | None -> ()
  );
  
  (* Nonce relationship analysis *)
  if List.length all_obs >= 2 then (
    print_endline "";
    print_endline "=================================================";
    print_endline "  Nonce Relationship Analysis";
    print_endline "=================================================";
    print_endline "";
    
    let obs1 = List.nth all_obs 0 in
    let obs2 = List.nth all_obs 1 in
    let rel = Nonce.analyze_pair obs1 obs2 in
    print_endline (match rel with
      | Nonce.Unrelated -> "No relationship detected"
      | Nonce.Same_nonce r -> Printf.sprintf "Same nonce detected: r = %s" (Z.to_string r)
      | Nonce.Related_nonce {r1=_; r2=_; z1=_; z2=_; similarity} ->
        Printf.sprintf "Related nonces (similarity: %.2f%%)" (similarity *. 100.0)
      | Nonce.HNP_candidate {r_values=_; z_values=_; hnp} -> 
        Printf.sprintf "HNP candidate detected (leaked bits: %d)" hnp.leaked_bits
    );
    
    let results = Nonce.analyze_transaction "CROSS" [all_obs] in
    print_endline "";
    List.iter (fun r ->
      print_endline (Nonce.format_result r)
    ) results
  );
  
  (* Per-transaction analysis *)
  print_endline "";
  print_endline "=================================================";
  print_endline "  Per-Transaction Analysis";
  print_endline "=================================================";
  
  List.iter (fun (name, obs_list) ->
    print_endline "";
    print_endline (name ^ ": " ^ string_of_int (List.length obs_list) ^ " inputs analyzed");
    if obs_list <> [] then (
      let stats = Statistics.compute_aggregate_stats [obs_list] in
      print_endline (Printf.sprintf "  Valid signatures: %d/%d (%.1f%%)"
        stats.ecdsa_verification.verified_count
        (stats.ecdsa_verification.verified_count + stats.ecdsa_verification.failed_count)
        (stats.ecdsa_verification.verification_rate *. 100.0))
    )
  ) observations_per_tx;
  
  (* Risk assessment *)
  print_endline "";
  print_endline "=================================================";
  print_endline "  Risk Assessment";
  print_endline "=================================================";
  
  let max_risk = List.fold_left (fun max_risk (_, obs_list) ->
    if obs_list = [] then max_risk
    else
      let results = Nonce.analyze_transaction "SINGLE" [obs_list] in
      let tx_risk = List.fold_left (fun acc r -> max acc r.Nonce.risk_score) 0.0 results in
      max max_risk tx_risk
  ) 0.0 observations_per_tx in
  
  print_endline (Printf.sprintf "Overall cryptographic risk: %.2f/1.00" max_risk);
  (if max_risk > 0.8 then
     print_endline "CRITICAL: Serious cryptographic vulnerabilities detected!"
   else if max_risk > 0.5 then
     print_endline "WARNING: Potential cryptographic weaknesses detected"
   else
     print_endline "Status: No critical cryptographic vulnerabilities detected");
  
  print_endline "";
  print_endline "Analysis complete."

(* ------------------------------------------------------------------ entry point *)

let () =
  if Array.length Sys.argv < 4 then (
    print_usage ();
    exit 1
  );
  
  let tx1 = Sys.argv.(1) in
  let tx2 = Sys.argv.(2) in
  let tx3 = Sys.argv.(3) in
  
  analyze_transactions tx1 tx2 tx3