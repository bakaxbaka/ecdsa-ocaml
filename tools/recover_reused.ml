(* Scan the verified rows written by dump_rsz for reused ECDSA nonces. *)
let z_of_hex value = Z.of_string ("0x" ^ value)

let parse_pubkey value =
  if String.length value = 66 then Curve.Point.of_compressed value
  else Curve.Point.of_uncompressed value

let observation_of_csv_line line =
  match String.split_on_char ',' line with
  | [txid; input_index; _script_type; _sighash; r; s; z; pubkey; "true"; _note]
    when z <> "" && pubkey <> "" ->
    (match parse_pubkey pubkey with
     | Error _ -> None
     | Ok public_key ->
       try Some (Observation.make ~txid ~input_index:(int_of_string input_index)
                   ~r:(z_of_hex r) ~s:(z_of_hex s) ~z:(z_of_hex z) ~pubkey:public_key)
       with Invalid_argument _ -> None)
  | _ -> None

let read_observations path =
  let channel = open_in path in
  Fun.protect ~finally:(fun () -> close_in_noerr channel) (fun () ->
      ignore (input_line channel);
      let rec loop acc =
        match input_line channel with
        | line -> loop (match observation_of_csv_line line with Some row -> row :: acc | None -> acc)
        | exception End_of_file -> List.rev acc
      in loop [])

let () =
  if Array.length Sys.argv <> 2 then begin
    prerr_endline "usage: recover_reused rsz_database.csv"; exit 2
  end;
  read_observations Sys.argv.(1)
  |> Sig_analysis.recover_private_keys
  |> List.iter (fun recovered ->
      Printf.printf "private_key=%064x pubkey=%s first=%s:%d second=%s:%d\n"
        recovered.private_key (Curve.Point.to_compressed recovered.public_key)
        recovered.first.txid recovered.first.input_index
        recovered.second.txid recovered.second.input_index)
