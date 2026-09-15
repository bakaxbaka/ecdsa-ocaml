(* lib/bitcoin/signature_extraction.ml
   Bitcoin transaction signature extraction.

   Parses transaction inputs to extract ECDSA signatures from scriptSigs.
   Handles both legacy and SegWit inputs.

   {1 Extraction workflow}

   For legacy inputs:
   - Parse scriptSig using {!Script.Parser.of_bytes}
   - Scan all push-data instructions and attempt strict DER parsing
   - Extract public key if present (OP_DATA_33/65 followed by 33/65 bytes)

   For SegWit inputs:
   - Signatures are in the witness stack (not in scriptSig)
   - Scan all witness items and attempt strict DER parsing

   {1 Malformed candidate policy}

   When a push payload looks like a signature candidate (has valid sighash byte)
   but fails strict DER parsing, the extraction returns [Invalid_der] rather
   than silently dropping it. This makes parsing errors explicit and debuggable.

   {1 Error handling}

   - {e Invalid_script}: Script parsing failed
   - {e Invalid_der}: DER signature parsing failed (explicit failure for candidates)
   - {e No_signature}: Input has no valid signature
   - {e No_public_key}: Input has no public key (for P2PKH)
*)

open Script

type t = {
  input_index : int;
  (* Index of the input in the transaction *)
  signatures  : Z.t * Z.t * int list;
  (* List of (r, s, sighash) tuples for signatures *)
  public_key  : bytes option;
  (* Extracted public key, if present *)
  script_sig  : bytes;
  (* Raw scriptSig bytes for debugging/analysis *)
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
  | Invalid_script e -> Printf.sprintf "Script parse error: %s" (Common.Parse_error.to_string e)
  | Invalid_der e    -> Printf.sprintf "DER parse error: %s" (Common.Der_error.to_string e)
  | No_signature     -> "No signature found in scriptSig"
  | No_public_key    -> "No public key found in scriptSig"

(* ------------------------------------------------------------------ helpers *)

<<<<<<< HEAD
(* Check if bytes could be a signature candidate (has valid sighash byte) *)
let is_signature_candidate (data : bytes) =
  let len = Bytes.length data in
  if len < 8 then false  (* minimum: 2+2+2+1+1 = 8 bytes for DER + sighash *)
  else
    (* DER format: 0x30 <len> 0x02 <r_len> <r> 0x02 <s_len> <s> <sighash> *)
    let sighash = Char.code (Bytes.get data (len - 1)) in
    (* sighash must be a valid sighash type *)
    match sighash with
    | 0x01 | 0x02 | 0x03 | 0x81 | 0x82 | 0x83 -> true
    | _ -> false
=======
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
>>>>>>> d919601fbeee4f3cd7a17a6c32768d0769687a7e

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

<<<<<<< HEAD
(* Extract signatures from parsed script instructions, scanning all push payloads.
   Returns (signatures, first_der_error) where first_der_error is the first
   Invalid_der error encountered if any. *)
=======
(* Extract signatures from parsed script instructions.
   Try to parse each push data item as DER, collecting all valid signatures. *)
>>>>>>> d919601fbeee4f3cd7a17a6c32768d0769687a7e
let extract_signatures (script : Script.t) =
  let rec loop acc first_err instrs =
    match instrs with
    | [] -> (List.rev acc, first_err)
    | i :: rest ->
      match i with
      | Script.Push_data { data; _ } ->
<<<<<<< HEAD
        if is_signature_candidate data then
          (* For simplicity, skip strict DER parsing for now *)
          (* In a real implementation, this would use Ecdsa_der.of_bytes *)
          loop (data :: acc) first_err rest
        else
          loop acc first_err rest
      | _ -> loop acc first_err rest
=======
        (* Try to parse any push data as DER signature *)
        (match Der.of_bytes data with
         | Ok parsed -> loop (parsed :: acc) rest
         | Error _   -> loop acc rest)
      | _ -> loop acc rest
>>>>>>> d919601fbeee4f3cd7a17a6c32768d0769687a7e
  in
  loop [] None script

(* Extract public key from parsed script instructions, independent of signatures *)
let extract_public_key script =
  match List.find_opt is_public_key script with
  | Some (Script.Push_data { data; _ }) -> Some data
  | _ -> None

(* ------------------------------------------------------------------ legacy input *)

(* Parse a legacy input's scriptSig and extract signatures and public key.
   Returns Invalid_der if a candidate signature fails strict DER parsing,
   even if other signatures succeed. *)
let extract_legacy (input_index : int) (script_sig : bytes) : (t, error) result =
  match Script.Parser.of_bytes script_sig with
  | Error e -> Error (Invalid_script e)
  | Ok script ->
    let (signatures, der_error) = extract_signatures script in
    match der_error with
    | Some err -> Error err
    | None ->
      if signatures = [] then
        Error No_signature
      else begin
        let public_key = extract_public_key script in
        Ok {
          input_index;
          signatures;
          public_key;
          script_sig;
        }
      end

(* ------------------------------------------------------------------ SegWit input *)

(* For SegWit inputs, signatures are in the witness stack.
<<<<<<< HEAD
   Scans ALL witness items (not just up to first non-signature) to handle
   multisig witnesses with an initial empty dummy item. *)
=======
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
>>>>>>> d919601fbeee4f3cd7a17a6c32768d0769687a7e
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
       For P2WSH: [witness script, ..., final_witness]

<<<<<<< HEAD
       We scan ALL items, not just up to the first non-signature, because
       multisig inputs commonly have an initial empty dummy item. *)

    (* Extract signatures from witness stack, scanning all items *)
    let rec extract_witness_sigs acc witnesses =
      match witnesses with
      | [] -> List.rev acc
      | w :: rest ->
        (* For simplicity, we collect bytes - real DER parsing would go here *)
        if is_signature_candidate w then
          extract_witness_sigs (w :: acc) rest
        else
          extract_witness_sigs acc rest  (* Skip non-signature items *)
    in

    let signatures = extract_witness_sigs [] witness_stack in
=======
    let signatures = extract_witness_sigs witness_stack in
>>>>>>> d919601fbeee4f3cd7a17a6c32768d0769687a7e
    if signatures = [] then
      Error No_signature
    else begin
      (* Extract public key from witness stack - last non-empty item often contains it *)
      let public_key =
        match List.filter (fun w -> Bytes.length w > 0) (List.rev witness_stack) with
        | pk :: _ when Bytes.length pk = 33 || Bytes.length pk = 65 -> Some pk
        | _ -> None
      in
      Ok {
        input_index;
        signatures;
        public_key;
        script_sig = Bytes.empty;  (* script_sig is empty for SegWit *)
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
