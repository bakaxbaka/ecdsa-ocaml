(*
  bin/extract_vectors.ml
  Extract r, s, z vectors from Bitcoin transactions for deep cryptographic analysis

  Usage: dune exec -- bin/extract_vectors.exe <tx1_hex> <tx2_hex> <tx3_hex> <output_file>
*)

open Analysis_signature.Observation

let parse_tx_hex h = Tx_parser.of_hex h

(* ------------------------------------------------------------------ utilities *)

let hex_of_bytes (b : bytes) : string =
  let hex_chars = "0123456789abcdef" in
  let result = Bytes.create (2 * Bytes.length b) in
  for i = 0 to Bytes.length b - 1 do
    let byte = int_of_char (Bytes.get b i) in
    Bytes.set result (2 * i) hex_chars.[byte lsr 4];
    Bytes.set result (2 * i + 1) hex_chars.[byte land 0x0F];
  done;
  Bytes.to_string result

(* ------------------------------------------------------------------ main *)

let extract_and_save (tx1_input : string) (tx2_input : string) (tx3_input : string) (output_file : string) : unit =
  print_endline "";
  print_endline "=================================================";
  print_endline "  ECDSA Vector Extraction Tool";
  print_endline "=================================================";
  print_endline "";
  
  (* Helper to read transaction *)
  let load_tx name input =
    let hex = 
      if Sys.file_exists input then (
        print_endline ("Reading " ^ name ^ " from file: " ^ input);
        let ic = open_in input in
        let content = really_input_string ic (in_channel_length ic) in
        close_in ic;
        String.trim content
      )
      else (
        print_endline ("Using " ^ name ^ " as raw hex");
        input
      )
    in
    match parse_tx_hex hex with
    | Ok tx -> (name, tx)
    | Error e ->
      Printf.eprintf "Error parsing %s: %s\n" name (Common.Parse_error.to_string e);
      exit 1
  in
  
  let transactions = [
    load_tx "TX1" tx1_input;
    load_tx "TX2" tx2_input;
    load_tx "TX3" tx3_input;
  ] in
  
  (* Extract observations and build CSV *)
  let csv_lines = ref ["tx_id,input_index,r,s,z,pubkey,sighash"] in
  
  List.iter (fun (name, tx) ->
    print_endline ("Extracting signatures from " ^ name ^ "...");
    let txid = Hex.of_bytes (Bytes.of_string name) in
    let results = Analysis_signature.Observation.build_all tx txid [] [] in
    
    List.iter (fun (idx, result) ->
      match result with
      | Ok obs ->
        let r_str = Z.to_string obs.r in
        let s_str = Z.to_string obs.s in
        let z_str = match obs.z with
          | Some z -> Z.to_string z
          | None -> "NONE"
        in
        let pubkey_str = obs.public_key_hex in
        let sighash_str = string_of_int obs.sighash_type in
        let line = Printf.sprintf "%s,%d,%s,%s,%s,%s,%s" 
          name idx r_str s_str z_str pubkey_str sighash_str in
        csv_lines := !csv_lines @ [line]
      | Error e ->
        Printf.eprintf "Error extracting observation %d: %s\n" idx (Analysis_signature.Observation.error_to_string e)
    ) results
  ) transactions;
  
  (* Write CSV file *)
  print_endline "";
  print_endline ("Writing " ^ string_of_int (List.length !csv_lines - 1) ^ " vectors to " ^ output_file ^ "...");
  let oc = open_out output_file in
  List.iter (fun line ->
    output_string oc line;
    output_char oc '\n'
  ) !csv_lines;
  close_out oc;
  
  print_endline "Extraction complete.";
  print_endline ""

let () =
  if Array.length Sys.argv < 5 then (
    print_endline "Usage: extract_vectors <tx1> <tx2> <tx3> <output_file>";
    print_endline "";
    print_endline "Arguments:";
    print_endline "  tx1, tx2, tx3: Raw hex or file paths to transactions";
    print_endline "  output_file: CSV file to save vectors";
    exit 1
  );
  
  let tx1 = Sys.argv.(1) in
  let tx2 = Sys.argv.(2) in
  let tx3 = Sys.argv.(3) in
  let output_file = Sys.argv.(4) in
  
  extract_and_save tx1 tx2 tx3 output_file

open Analysis_signature.Observation
