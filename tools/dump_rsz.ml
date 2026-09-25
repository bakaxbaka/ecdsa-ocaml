(* Produce verified r,s,z observations from a directory of raw transaction hex.
   Usage: dump_rsz RAWTX_DIR OUTPUT.csv

   Files are expected to be named <display-txid>.hex.  The directory is first
   indexed so SegWit inputs can obtain the scriptPubKey and amount of parents
   included in the same corpus. *)

let read_file path =
  let channel = open_in path in
  Fun.protect ~finally:(fun () -> close_in_noerr channel) (fun () ->
      let length = in_channel_length channel in
      really_input_string channel length |> String.trim)

let hex = Hex.of_bytes
let z_of_bytes = Verify.z_of_bytes
let p2pkh_script hash160 =
  Bytes.concat Bytes.empty [Bytes.of_string "\x76\xa9\x14"; hash160;
                           Bytes.of_string "\x88\xac"]

let is_p2pkh script =
  Bytes.length script = 25
  && Bytes.get script 0 = '\x76' && Bytes.get script 1 = '\xa9'
  && Bytes.get script 2 = '\x14' && Bytes.get script 23 = '\x88'
  && Bytes.get script 24 = '\xac'

let witness_program script =
  let n = Bytes.length script in
  if n = 22 && Bytes.get script 0 = '\x00' && Bytes.get script 1 = '\x14'
  then Some (`Wpkh, Bytes.sub script 2 20)
  else if n = 34 && Bytes.get script 0 = '\x00' && Bytes.get script 1 = '\x20'
  then Some (`Wsh, Bytes.sub script 2 32)
  else None

let is_p2sh script =
  Bytes.length script = 23 && Bytes.get script 0 = '\xa9'
  && Bytes.get script 1 = '\x14' && Bytes.get script 22 = '\x87'

let is_p2pk script =
  let n = Bytes.length script in
  n >= 2 && Bytes.get script (n - 1) = '\xac'
  && let push = Char.code (Bytes.get script 0) in push + 2 = n

let pushes bytes =
  match Script.Parser.of_bytes bytes with
  | Error _ -> []
  | Ok instructions ->
    List.filter_map (function Script.Push_data { data; _ } -> Some data | _ -> None)
      instructions

let signatures values = List.filter_map (fun value ->
    match Der.of_bytes value with
    | Error _ -> None
    | Ok der -> Option.map (fun signature -> (der, signature)) (Signature.of_der der)) values

let point_of_push = function
  | None -> None
  | Some point when Bytes.length point = 33 ->
    Result.to_option (Curve.Point.of_compressed (hex point))
  | Some point when Bytes.length point = 65 ->
    Result.to_option (Curve.Point.of_uncompressed (hex point))
  | Some _ -> None

let first_public_key values =
  values |> List.find_opt (fun item -> let n = Bytes.length item in n = 33 || n = 65)
  |> point_of_push

let last_push bytes = match List.rev (pushes bytes) with value :: _ -> Some value | [] -> None

type prevout = { script : bytes; value : Int64.t }

let add_transaction_outputs index txid (transaction : Types.transaction) =
  List.iteri (fun vout output ->
      Hashtbl.replace index (txid, vout) { script = output.script_pubkey; value = output.value })
    transaction.outputs

let write_row channel fields =
  output_string channel (String.concat "," fields ^ "\n")

let emit_signature channel ~txid ~input_index ~script_type ~der ~signature ~pubkey ~z ~note =
  let valid = match pubkey, z with
    | Some public_key, Some digest -> Verify.verify_bytes ~pubkey:public_key ~hash_bytes:digest signature
    | _ -> false
  in
  write_row channel [txid; string_of_int input_index; script_type;
                     string_of_int der.Der.sighash;
                     Z.format "%064x" (Signature.r signature);
                     Z.format "%064x" (Signature.s signature);
                     Option.value_map z ~default:"" ~f:hex;
                     Option.value_map pubkey ~default:"" ~f:Curve.Point.to_compressed;
                     string_of_bool valid; note]

let process_input channel index txid transaction input_index input =
  let previous = Hashtbl.find_opt index
      (Types.txid_to_display_hex input.Types.previous_output.txid, input.Types.previous_output.vout) in
  let witness = if transaction.Types.segwit then
      Option.value ~default:[] (List.nth_opt transaction.Types.witnesses input_index) else [] in
  let values = if transaction.Types.segwit then witness else pushes input.Types.script_sig in
  let signatures = signatures values in
  let prev_script = Option.map (fun output -> output.script) previous in
  let script_type, script_code, amount, public_key, note =
    match prev_script with
    | Some script when is_p2pkh script ->
      ("p2pkh", Some script, None, first_public_key values, "")
    | Some script when is_p2sh script ->
      let redeem = last_push input.Types.script_sig in
      (match redeem with
       | Some redeem_script ->
         (match witness_program redeem_script with
          | Some (`Wpkh, hash160) ->
            ("p2sh-p2wpkh", Some (p2pkh_script hash160),
             Option.map (fun x -> x.value) previous, first_public_key values, "")
          | Some (`Wsh, _) ->
            let witness_script = match List.rev witness with item :: _ -> Some item | [] -> None in
            ("p2sh-p2wsh", witness_script, Option.map (fun x -> x.value) previous,
             first_public_key (List.rev witness),
             if Option.is_some witness_script then "" else "missing_witness_script")
          | None -> ("p2sh", Some redeem_script, None, first_public_key values, ""))
       | None -> ("p2sh", None, None, first_public_key values, "missing_redeem_script"))
    | Some script ->
      (match witness_program script with
       | Some (`Wpkh, hash160) ->
         ("p2wpkh", Some (p2pkh_script hash160), Option.map (fun x -> x.value) previous,
          first_public_key values, "")
       | Some (`Wsh, _) ->
         let witness_script = match List.rev witness with item :: _ -> Some item | [] -> None in
         ("p2wsh", witness_script, Option.map (fun x -> x.value) previous,
          first_public_key (List.rev witness),
          if Option.is_some witness_script then "" else "missing_witness_script")
       | None when is_p2pk script ->
         let key = if Bytes.length script = 35 || Bytes.length script = 67
                   then Bytes.sub script 1 (Bytes.length script - 2) else Bytes.empty in
         ("p2pk", Some script, None, point_of_push (Some key), "")
       | None -> ("unknown", None, None, first_public_key values, "unsupported_prevout_script"))
    | None -> ("unknown", None, None, first_public_key values, "missing_prevout")
  in
  List.iter (fun (der, signature) ->
      let z, computation_note = match script_code with
        | None -> (None, note)
        | Some code ->
          (match amount with
           | Some value ->
             (match Bip143.compute transaction input_index code value der.Der.sighash with
              | Ok digest -> (Some digest, note) | Error _ -> (None, "invalid_sighash"))
           | None ->
             (match Legacy.compute transaction input_index code der.Der.sighash with
              | Ok digest -> (Some digest, note) | Error _ -> (None, "invalid_sighash")))
      in
      emit_signature channel ~txid ~input_index ~script_type ~der ~signature ~pubkey:public_key
        ~z ~note:computation_note) signatures

let hex_files directory =
  Sys.readdir directory |> Array.to_list |> List.filter (Filename.check_suffix ".hex") |> List.sort String.compare

let () =
  if Array.length Sys.argv <> 3 then begin
    prerr_endline "usage: dump_rsz RAWTX_DIR OUTPUT.csv"; exit 2
  end;
  let directory, output = Sys.argv.(1), Sys.argv.(2) in
  let files = hex_files directory in
  let index = Hashtbl.create (max 16 (List.length files * 2)) in
  List.iter (fun file ->
      let txid = Filename.chop_suffix file ".hex" in
      match Parser.of_hex (read_file (Filename.concat directory file)) with
      | Ok transaction -> add_transaction_outputs index txid transaction
      | Error _ -> ()) files;
  let channel = open_out output in
  Fun.protect ~finally:(fun () -> close_out_noerr channel) (fun () ->
      write_row channel ["txid"; "input_index"; "script_type"; "sighash_type";
                         "r_hex"; "s_hex"; "z_hex"; "pubkey_hex"; "ecdsa_valid"; "note"];
      List.iter (fun file ->
          let txid = Filename.chop_suffix file ".hex" in
          match Parser.of_hex (read_file (Filename.concat directory file)) with
          | Error _ -> ()
          | Ok transaction -> List.iteri (process_input channel index txid transaction) transaction.Types.inputs)
        files)
