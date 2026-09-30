(* tools/scan_dir.ml
   OCaml walker: dir → intermediate CSV (no z yet)

   Reads every .hex file in input_dir, parses the transaction, extracts
   signature components (r, s, sighash) and metadata (pubkey, prevout, script_type),
   writes one row per input to intermediate.csv.

   The CSV format is fixed at 11 columns so downstream parsing is positional:
   txid,input_index,prevout_txid,prevout_index,pubkey_hex,r_hex,s_hex,sighash,script_type,z_hex,note
*)

open Common
open Common
open Types
open Signature_extraction
open Analysis_signature.Observation

let read_file path =
  let ic = open_in_bin path in
  let n = in_channel_length ic in
  let s = really_input_string ic n in
  close_in ic;
  s

let hex_of_reversed_bytes b =
  (* prevout hashes on the wire are little-endian; display form is reversed *)
  let n = Bytes.length b in
  let rev = Bytes.create n in
  for i = 0 to n - 1 do
    Bytes.set rev i (Bytes.get b (n - 1 - i))
  done;
  Hex.of_bytes rev

(* Try to determine script type without spk_hint; return a string *)
let script_type_string tx txid input_index =
  match build_observation tx txid input_index None None with
  | Ok obs -> Classify.to_string obs.script_type
  | Error _ -> "unknown"

(* Process one .hex file and write rows to oc *)
let process_one oc path =
  let base = Filename.basename path in
  let txid = Filename.chop_suffix base ".hex" in
  try
    let hex = read_file path in
    match Tx_parser.of_hex hex with
    | Error e ->
      Printf.eprintf "%s: parse error: %s\n" base (Parse_error.to_string e)
    | Ok tx ->
      List.iteri (fun i inp ->
        (* Get script type *)
        let stype = script_type_string tx txid i in
        (* Extract sig + pubkey directly *)
        match Signature_extraction.extract_single tx i with
        | Error _ ->
          Printf.fprintf oc "%s,%d,%s,%d,,,,,unknown,,parse_error\n"
            txid i (hex_of_reversed_bytes inp.previous_output.txid) inp.previous_output.vout
        | Ok ex ->
          (match ex.signatures with
           | [] ->
             Printf.fprintf oc "%s,%d,%s,%d,,,,,%s,,nosig\n"
               txid i (hex_of_reversed_bytes inp.previous_output.txid) inp.previous_output.vout stype
           | psig :: _ ->
             let pk_hex = match ex.public_key with
               | None -> ""
               | Some b -> Hex.of_bytes b
             in
             Printf.fprintf oc "%s,%d,%s,%d,%s,%s,%s,%s,%s,,\n"
               txid i
               (hex_of_reversed_bytes inp.previous_output.txid)
               inp.previous_output.vout
               pk_hex
               (Z.format "%064x" psig.r)
               (Z.format "%064x" psig.s)
               (Printf.sprintf "%02x" psig.sighash)
               stype)
      ) tx.inputs
  with e ->
    Printf.eprintf "%s: %s\n" base (Printexc.to_string e)

let () =
  if Array.length Sys.argv < 3 then begin
    Printf.eprintf "usage: %s <input_dir> <intermediate.csv>\n" Sys.argv.(0);
    exit 1
  end;
  let dir = Sys.argv.(1) in
  let out = Sys.argv.(2) in
  let oc = open_out out in
  output_string oc
    "txid,input_index,prevout_txid,prevout_index,pubkey_hex,r_hex,s_hex,sighash,script_type,z_hex,note\n";
  let files = Sys.readdir dir in
  Array.sort compare files;
  Array.iter (fun f ->
    if Filename.check_suffix f ".hex" then
      process_one oc (Filename.concat dir f)
  ) files;
  close_out oc