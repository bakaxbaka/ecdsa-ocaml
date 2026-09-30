(* tools/recover_reused.ml
   Scan the verified rows written by dump_rsz for reused ECDSA nonces.

   Usage:  recover_reused rsz_database.csv

   Adapted to the merged analysis API. The incoming version of this tool was
   written against a different analysis layer: it expected
   [recover_private_keys : Observation.t list -> recovered_key list] and read
   [recovered.private_key], [recovered.public_key], [recovered.first.txid].
   The surviving [Analysis_signature.Sig_analysis.recover_private_keys] takes [signature_record list]
   and returns [(Z.t * signature_record * signature_record) list] — the key plus
   the pair it came from — and [signature_record] identifies its transaction as
   [tx_id], not [txid].

   Input is the ten-column output of dump_rsz.exe:

     txid,input_index,script_type,sighash_type,r_hex,s_hex,z_hex,pubkey_hex,ecdsa_valid,note

   Only rows with ecdsa_valid = true are considered. That column is the quality
   gate: it is set by actually verifying the signature against the extracted
   public key and the computed message hash, so a row that survives it has a
   genuine (r, s, z) triple. Rows with an empty z_hex have no computed sighash
   and cannot contribute to recovery. *)

let z_of_hex value = Z.of_string ("0x" ^ value)

let observation_of_row line =
  match String.split_on_char ',' line with
  | [ txid; input_index; _script_type; _sighash; r; s; z; pubkey; "true"; _note ]
    when z <> "" && pubkey <> "" ->
    (match int_of_string_opt input_index with
     | None -> None
     | Some index ->
       try
         Some
           { Analysis_signature.Sig_analysis.tx_id = txid;
             input_index = index;
             pubkey = Some pubkey;
             r = z_of_hex r;
             s = z_of_hex s;
             z = Some (z_of_hex z);
             timestamp = None }
       with Invalid_argument _ -> None)
  | _ -> None

let read_records path =
  let channel = open_in path in
  Fun.protect
    ~finally:(fun () -> close_in_noerr channel)
    (fun () ->
       (* Discard the header row. *)
       ignore (input_line channel);
       let rec loop acc =
         match input_line channel with
         | line -> loop (match observation_of_row line with Some row -> row :: acc | None -> acc)
         | exception End_of_file -> List.rev acc
       in
       loop [])

(* [recover_private_keys] already filters pairs whose z values are equal (those
   are duplicates, not reuse) and whose r differs, and it derives d from the
   closed-form solution. What it does not do is prove the result, so the
   candidate is checked here by deriving d*G and comparing against the public key
   recorded for the rows. That keeps a wrong candidate out of the output. *)
let verify_candidate private_key pubkey_hex =
  let derived =
    Curve.Point.scalar_mul (Scalar.of_z private_key) Curve.Point.generator
  in
  match Curve.Point.of_compressed pubkey_hex with
  | Error _ -> false
  | Ok expected -> Curve.Point.equal derived expected

let () =
  if Array.length Sys.argv <> 2 then begin
    prerr_endline "usage: recover_reused rsz_database.csv";
    exit 2
  end;
  let records = read_records Sys.argv.(1) in
  Printf.eprintf "read %d verified signature row(s)\n%!" (List.length records);
  let recovered = Analysis_signature.Sig_analysis.recover_private_keys records in
  let reported = ref 0 and unverified = ref 0 in
  List.iter
    (fun ((private_key : Z.t), first, second) ->
       let xprv =
         Z.format "%064x" private_key
       in
       (* Confirm against whichever public key the rows carry. *)
       let confirmed =
         match first.Analysis_signature.Sig_analysis.pubkey, second.Analysis_signature.Sig_analysis.pubkey with
         | Some pk, _ | _, Some pk -> verify_candidate private_key pk
         | None, None -> false
       in
       if confirmed then begin
         incr reported;
         Printf.printf "private_key=%s first=%s:%d second=%s:%d\n" xprv
           first.Analysis_signature.Sig_analysis.tx_id first.Analysis_signature.Sig_analysis.input_index
           second.Analysis_signature.Sig_analysis.tx_id second.Analysis_signature.Sig_analysis.input_index
       end else begin
         incr unverified;
         Printf.eprintf "candidate for %s:%d / %s:%d did NOT verify against d*G; withheld\n%!"
           first.Analysis_signature.Sig_analysis.tx_id first.Analysis_signature.Sig_analysis.input_index
           second.Analysis_signature.Sig_analysis.tx_id second.Analysis_signature.Sig_analysis.input_index
       end)
    recovered;
  Printf.eprintf "%d key(s) reported, %d candidate(s) withheld as unverified\n%!"
    !reported !unverified
