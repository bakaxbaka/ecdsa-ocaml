(* lib/bitcoin/signature_extraction.ml
   Bitcoin transaction signature extraction.

   Parses transaction inputs to extract ECDSA signatures from scriptSigs.
   Handles both legacy and SegWit inputs.

   {1 Extraction workflow}

   For legacy inputs:
   - Parse scriptSig using {!Script.Parser.of_bytes}
   - Extract DER-encoded signatures (OP_DATA_71/72/73 followed by 71/72/73 bytes)
   - Parse DER signatures using {!Der.of_bytes}
   - Extract public key if present (OP_DATA_33/65 followed by 33/65 bytes)

   For SegWit inputs:
   - Signatures are in the witness stack (not in scriptSig)
   - Script code is in the scriptPubKey of the spent output

   {1 Error handling}

   - {e Invalid_script}: Script parsing failed
   - {e Invalid_der}: DER signature parsing failed
   - {e No_signature}: Input has no signature
   - {e No_public_key}: Input has no public key (for P2PKH)
*)

type t = {
  input_index : int;
  (* Index of the input in the transaction *)
  signatures  : Der.parsed list;
  (* List of DER signatures (for multi-signature inputs) *)
  public_key  : bytes option;
  (* Extracted public key, if present *)
  script_sig  : Script.t;
  (* Parsed scriptSig for debugging/analysis *)
}

type error =
  | Invalid_script of Common.Parse_error.t
  | Invalid_der    of Common.Der_error.t
  | No_signature
  | No_public_key

let error_to_string = function
  | Invalid_script e -> Printf.sprintf "Script parse error: %s" (Common.Parse_error.to_string e)
  | Invalid_der e    -> Printf.sprintf "DER parse error: %s" (Common.Der_error.to_string e)
  | No_signature     -> "No signature found in scriptSig"
  | No_public_key    -> "No public key found in scriptSig"

(* ------------------------------------------------------------------ helpers *)

(* Check if an instruction is a DER-encoded signature.
   Accept any valid push data that could be a DER signature (typically 70-73 bytes).
   We check for OP_PUSHDATA opcodes and reasonable lengths rather than hardcoding. *)
let is_der_signature instr =
  match instr with
  | Script.Push_data { opcode; data } ->
    (* DER signatures have a minimum length and reasonable maximum.
       The opcode indicates the push length. Accept all standard push opcodes. *)
    let len = Bytes.length data in
    (* Valid DER signatures are at least ~8 bytes and at most ~73 bytes plus sighash *)
    len >= 8 && len <= 74 && opcode >= 0x01 && opcode <= 0x4b
  | _ -> false

(* Check if an instruction is a public key push *)
let is_public_key instr =
  match instr with
  | Script.Push_data { opcode; data } ->
    (* Compressed public keys are 33 bytes (opcode 0x21)
       Uncompressed are 65 bytes (opcode 0x41) *)
    let len = Bytes.length data in
    (len = 33 && opcode = 0x21) ||
    (len = 65 && opcode = 0x41)
  | _ -> false

(* Extract signatures from parsed script instructions.
   Try to parse each push data item as DER, collecting all valid signatures. *)
let extract_signatures (script : Script.t) =
  let rec loop acc instrs =
    match instrs with
    | [] -> List.rev acc
    | i :: rest ->
      match i with
      | Script.Push_data { data; _ } ->
        (* Try to parse any push data as DER signature *)
        (match Der.of_bytes data with
         | Ok parsed -> loop (parsed :: acc) rest
         | Error _   -> loop acc rest)
      | _ -> loop acc rest
  in
  loop [] script

(* Extract public key from parsed script instructions *)
let extract_public_key script =
  Script.data_of
    (List.find_opt is_public_key script
     |> Option.value ~default:(Script.Opcode 0x00))

(* ------------------------------------------------------------------ legacy input *)

(* Parse a legacy input's scriptSig and extract signatures and public key *)
let extract_legacy (input_index : int) (script_sig : bytes) : (t, error) result =
  match Script.Parser.of_bytes script_sig with
  | Error e -> Error (Invalid_script e)
  | Ok script ->
    let signatures = extract_signatures script in
    if signatures = [] then
      Error No_signature
    else begin
      let public_key = extract_public_key script in
      Ok {
        input_index;
        signatures;
        public_key = if Bytes.length public_key = 0 then None else Some public_key;
        script_sig;
      }
    end

(* ------------------------------------------------------------------ SegWit input *)

(* For SegWit inputs, signatures are in the witness stack.
   Scan ALL witness items for valid DER signatures instead of stopping at the first non-signature. *)
let extract_witness_sigs witnesses =
  let rec loop acc stack =
    match stack with
    | [] -> List.rev acc
    | w :: rest ->
      (* Try to parse each witness item as DER signature *)
      (match Der.of_bytes w with
       | Ok parsed -> loop (parsed :: acc) rest
       | Error _   -> loop acc rest)
  in
  loop [] witnesses

(* For SegWit inputs, signatures are in the witness stack *)
let extract_segwit
    (input_index : int)
    (witness_stack : bytes list)
    (script_pubkey : bytes)
  : (t, error) result =
  if witness_stack = [] then
    Error No_signature
  else begin
    (* In SegWit, the witness stack contains: [signature..., final_witness, scriptCode]
       For P2WPKH: [signature, public_key]
       For P2WSH: [witness script, ..., final_witness] *)

    let signatures = extract_witness_sigs witness_stack in
    if signatures = [] then
      Error No_signature
    else begin
      (* Last item is usually the script code or public key *)
      let public_key =
        match List.rev witness_stack with
        | pk :: _ when Bytes.length pk = 33 || Bytes.length pk = 65 -> Some pk
        | _ -> None
      in
      Ok {
        input_index;
        signatures;
        public_key;
        script_sig = Script.empty;  (* script_sig is empty for SegWit *)
      }
    end
  end

(* ------------------------------------------------------------------ public API *)

(* [extract tx] extracts signatures from all inputs of a transaction.
   Returns a list of (input_index, signature_data) pairs or the first error. *)
let extract (tx : Types.transaction) : (t list, error) result =
  let rec loop acc inputs input_idx =
    match inputs with
    | [] -> Ok (List.rev acc)
    | inp :: rest ->
      if tx.segwit then
        (* SegWit: get witness from tx.witnesses *)
        let witness_idx = input_idx in
        let witness_stack =
          try List.nth tx.witnesses witness_idx with
          | Failure _ -> []
        in
        match extract_segwit input_idx witness_stack inp.previous_output.txid with
        | Error e as err -> err
        | Ok sig_data -> loop (sig_data :: acc) rest (input_idx + 1)
      else begin
        (* Legacy: parse scriptSig *)
        match extract_legacy input_idx inp.script_sig with
        | Error e as err -> err
        | Ok sig_data -> loop (sig_data :: acc) rest (input_idx + 1)
      end
  in
  loop [] tx.inputs 0

(* [extract_single tx input_index] extracts signatures from a specific input.
   Returns [Error] if input_index is out of bounds or extraction fails. *)
let extract_single (tx : Types.transaction) (input_index : int) : (t, error) result =
  let n_inputs = List.length tx.inputs in
  if input_index < 0 || input_index >= n_inputs then
    Error No_signature  (* reuse error type *)
  else
    let inp = List.nth tx.inputs input_index in
    if tx.segwit then
      let witness_idx = input_idx in
      let witness_stack =
        try List.nth tx.witnesses witness_idx with
        | Failure _ -> []
      in
      extract_segwit input_idx witness_stack inp.previous_output.txid
    else
      extract_legacy input_index inp.script_sig
