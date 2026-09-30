(*
   analyze_tx_signatures.ml
   Parse Bitcoin transactions, extract signatures, and analyze cryptographic patterns
   
   Usage: dune exec bin/analyze_tx_signatures -- <tx_hex_file1> <tx_hex_file2> ...
*)

open Types
open Parser
open Der
open Scalar
open Printf

(* Load hex transaction from file *)
let load_hex_file path =
  let ic = open_in path in
  let content = really_input_string ic (in_channel_length ic) in
  close_in ic;
  String.trim content

(* Convert hex string to bytes *)
let hex_to_bytes hex_str =
  let len = String.length hex_str in
  if len mod 2 <> 0 then invalid_arg "hex_to_bytes: odd length";
  let bytes = Bytes.create (len / 2) in
  for i = 0 to (len / 2) - 1 do
    let hex_byte = String.sub hex_str (i * 2) 2 in
    let byte = int_of_string ("0x" ^ hex_byte) in
    Bytes.set bytes i (Char.chr byte)
  done;
  bytes

(* Extract r, s from DER-encoded signature *)
let parse_der_signature sig_bytes =
  try
    match Der.of_bytes sig_bytes with
    | Ok sig_ ->
        Some sig_
    | Error _ -> None
  with _ -> None

(* Format Scalar as hex string *)
let scalar_to_hex scalar =
  let z = Scalar.to_z (Signature.r scalar) in
  Printf.sprintf "%064Lx" (Z.to_int64 z)

(* Parse scriptSig to extract signatures *)
let extract_signatures_from_scriptSig script_bytes =
  let rec parse_script offset sigs =
    if offset >= Bytes.length script_bytes then
      List.rev sigs
    else
      (* Read opcode/length *)
      let b = Bytes.get script_bytes offset in
      let len = Char.code b in
      
      if len > 250 || offset + len + 1 > Bytes.length script_bytes then
        List.rev sigs
      else
        let data = Bytes.sub script_bytes (offset + 1) len in
        let next_offset = offset + 1 + len in
        
        (* Try to parse as DER signature *)
        match parse_der_signature data with
        | Some sig_ -> parse_script next_offset (sig_ :: sigs)
        | None -> parse_script next_offset sigs
  in
  parse_script 0 []

(* Compute SIGHASH_ALL for legacy transaction *)
let compute_sighash_legacy tx input_index =
  (* Simplified: uses Sighash.legacy_sighash *)
  try
    match Legacy.compute tx i sc psig.sighash with
    | Ok hash -> Some hash
    | Error _ -> None
  with _ -> None

(* Analyze signatures from a transaction *)
let analyze_transaction tx_hex tx_label =
  printf "\n=== Analyzing %s ===\n" tx_label;
  
  let hex_str = load_hex_file tx_hex in
  let tx_bytes = hex_to_bytes hex_str in
  
  match Tx_parser.of_bytes tx_bytes with
  | Error err ->
      printf "Failed to parse transaction: %s\n" (Parse_error.to_string err);
      []
  | Ok tx ->
      printf "Parsed transaction with %d inputs\n" (List.length tx.inputs);
      
      let signatures = ref [] in
      
      (* Extract signatures from each input *)
      List.iteri (fun i input ->
        printf "\nInput %d:\n" i;
        printf "  Previous output: %s:%d\n" 
          (Hash256.to_hex input.previous_output.hash)
          input.previous_output.index;
        
        (* Parse scriptSig *)
        let sigs = extract_signatures_from_scriptSig input.script_sig in
        printf "  Found %d signature(s)\n" (List.length sigs);
        
        (* For each signature, compute message hash *)
        List.iteri (fun j sig_ ->
          match compute_sighash_legacy tx i with
          | Some msg_hash ->
              printf "    Signature %d:\n" j;
              printf "      r: %s\n" (Hash256.to_hex msg_hash); (* placeholder *)
              printf "      s: %s\n" (Hash256.to_hex msg_hash); (* placeholder *)
              printf "      z: %s\n" (Hash256.to_hex msg_hash);
              signatures := (i, j, sig_, msg_hash) :: !signatures
          | None ->
              printf "    Signature %d: Could not compute message hash\n" j
        ) sigs
      ) tx.inputs;
      
      !signatures

(* Main analysis *)
let () =
  let tx_files = [
    ("d:\\ecdsa-ocaml\\analysis\\tx_vectors\\2427823cf3781149b7b2ff221942e5ef23e86bcc2cc6c10a174ec889a591e031.hex", "TX1");
    ("d:\\ecdsa-ocaml\\analysis\\tx_vectors\\ef95039c03e4e7979b8211bb353fa0d636d4845f5fbcc462eb6ab01b506e5bc2.hex", "TX2");
    ("d:\\ecdsa-ocaml\\analysis\\tx_vectors\\d33ade0feef46c87e0d5422d3410a14d6630b49707fc819bfeda6ed7511b3fd4.hex", "TX3");
  ] in
  
  printf "Bitcoin Transaction Signature Analysis\n";
  printf "========================================\n";
  printf "Public Key: 03507a40492642239fc7eae74bc1f1beb15a6079ea3702cfdaeec2268bb00bcbd0\n";
  
  let all_sigs = ref [] in
  
  List.iter (fun (path, label) ->
    if Sys.file_exists path then
      let sigs = analyze_transaction path label in
      all_sigs := !all_sigs @ sigs
    else
      printf "File not found: %s\n" path
  ) tx_files;
  
  printf "\n=== Summary ===\n";
  printf "Total signatures analyzed: %d\n" (List.length !all_sigs);
  printf "\nMessage Hash Patterns:\n";
  
  (* Check for repeated message hashes *)
  let hash_counts = Hashtbl.create 100 in
  List.iter (fun (_, _, _, hash) ->
    let hash_hex = Hash256.to_hex hash in
    let count = try Hashtbl.find hash_counts hash_hex with Not_found -> 0 in
    Hashtbl.replace hash_counts hash_hex (count + 1)
  ) !all_sigs;
  
  Hashtbl.iter (fun hash_hex count ->
    if count > 1 then
      printf "  %s (found %d times)\n" hash_hex count
  ) hash_counts;
  
  printf "\nAnalysis complete.\n"
