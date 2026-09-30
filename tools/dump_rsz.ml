(* tools/dump_rsz.ml
   Process .hex files → CSV with r, s, z_hex, script_type
   
   For legacy inputs: derives script_code from scriptSig (P2PKH/P2SH heuristics)
   For SegWit inputs: z_hex = "" (prevout lookup needed for Bip143)
   
   Output format:
   txid,input_index,prevout_txid,prevout_index,pubkey_hex,r_hex,s_hex,script_type,sighash_type,z_hex
*)

open Signature_extraction

let read_file p =
  let ic = open_in_bin p in
  let n = in_channel_length ic in
  let s = really_input_string ic n in
  close_in ic; s

let rev_hex b =
  let n = Bytes.length b in
  let r = Bytes.create n in
  for i = 0 to n - 1 do Bytes.set r i (Bytes.get b (n - 1 - i)) done;
  Hex.of_bytes r

let pushes_of (bs : bytes) : bytes list =
  match Parser.of_bytes bs with
  | Error _ -> []
  | Ok instrs ->
    List.filter_map (function
      | Script.Push_data { data; _ } -> Some data
      | _ -> None) instrs

let is_curve_point (p : bytes) =
  (Bytes.length p = 33 || Bytes.length p = 65) &&
  (match Curve.Point.of_compressed (Hex.of_bytes p) with
   | Ok _ -> true
   | Error _ ->
     (match Curve.Point.of_uncompressed (Hex.of_bytes p) with
      | Ok _ -> true | Error _ -> false))

let p2pkh_sc (pk : bytes) : bytes =
  let h160 = Bytes.of_string
    Digestif.RMD160.(digest_bytes (Hash.sha256 pk) |> to_raw_string) in
  let sc = Bytes.create 25 in
  Bytes.set sc 0 '\x76'; Bytes.set sc 1 '\xa9'; Bytes.set sc 2 '\x14';
  Bytes.blit h160 0 sc 3 20;
  Bytes.set sc 23 '\x88'; Bytes.set sc 24 '\xac';
  sc

(* Returns (script_code, script_type_string) *)
let script_code_of_script_sig (ss : bytes) : bytes option * string =
  let pushes = pushes_of ss in
  match List.rev pushes with
  | [] -> (None, "unknown")
  | last :: _ when is_curve_point last ->
    (* P2PKH (last push is the pubkey) *)
    (Some (p2pkh_sc last), "P2PKH")
  | [_last] ->
    (* Single non-curve push — could be P2PK (unsupported), P2SH-P2WPKH (22 B),
       P2SH-P2WSH (34 B). Only classify as P2SH if length matches known witness. *)
    let n = Bytes.length (List.hd pushes) in
    if n = 22 || n = 34 then (None, "P2SH-segwit-unsupported")
    else (None, "P2PK-or-unknown")
  | last :: _ ->
    (* P2SH (last push is the redeemScript). Heuristic: >= 20 bytes. *)
    if Bytes.length last >= 20 then (Some last, "P2SH")
    else (None, "unknown")

let process_tx oc path =
  let base = Filename.basename path in
  let txid = Filename.chop_suffix base ".hex" in
  try
    let hex = read_file path in
    match Tx_parser.of_hex hex with
    | Error e -> Printf.eprintf "%s: %s\n" base (Common.Parse_error.to_string e)
    | Ok tx ->
      let n_in = List.length tx.inputs in
      for i = 0 to n_in - 1 do
        let inp = List.nth tx.inputs i in
        let prev_txid = rev_hex inp.previous_output.txid in
        let prev_idx = inp.previous_output.vout in
        (* Script code from scriptSig (legacy inputs only) *)
        let sc_opt, stype = script_code_of_script_sig inp.script_sig in
        match Signature_extraction.extract_single tx i with
        | Error _ -> ()
        | Ok ex ->
          (match ex.signatures with
           | [] -> ()
           | sigs ->
             let pubkey_hex = match ex.public_key with
               | None -> ""
               | Some b -> Hex.of_bytes b
             in
             List.iter (fun psig ->
               let z_hex =
                 match sc_opt with
                 | None -> ""
                 | Some sc ->
                   (match Legacy.compute tx i sc psig.sighash with
                    | Ok h -> Hex.of_bytes h
                    | Error _ -> "")
               in
               Printf.fprintf oc "%s,%d,%s,%d,%s,%s,%s,%s,%02x,%s\n"
                 txid i prev_txid prev_idx
                 pubkey_hex
                 (Z.format "%064x" psig.r)
                 (Z.format "%064x" psig.s)
                 stype
                 psig.sighash
                 z_hex)
             sigs)
      done
  with e -> Printf.eprintf "%s: %s\n" base (Printexc.to_string e)

let () =
  if Array.length Sys.argv < 3 then begin
    Printf.eprintf "usage: %s <input_dir> <output.csv>\n" Sys.argv.(0);
    exit 1
  end;
  let dir = Sys.argv.(1) and out = Sys.argv.(2) in
  let oc = open_out out in
  output_string oc
    "txid,input_index,prevout_txid,prevout_index,pubkey_hex,r_hex,s_hex,script_type,sighash_type,z_hex\n";
  let files = Sys.readdir dir in
  Array.sort compare files;
  let processed = ref 0 in
  Array.iter (fun f ->
    if Filename.check_suffix f ".hex" then begin
      process_tx oc (Filename.concat dir f);
      incr processed;
      if !processed mod 500 = 0 then
        Printf.eprintf "  %d files processed\n" !processed
    end
  ) files;
  Printf.eprintf "  %d files total\n" !processed;
  close_out oc