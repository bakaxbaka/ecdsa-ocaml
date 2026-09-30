(* lib/bitcoin/signature_extraction.ml
   Bitcoin transaction signature extraction.

   Parses transaction inputs to extract ECDSA signatures from scriptSigs
   (legacy) and witness stacks (SegWit).

   {1 Extraction workflow}

   For legacy inputs:
   - Parse scriptSig using {!Script.Parser.of_bytes}
   - Scan ALL push-data instructions for strict DER-encoded signatures
   - Extract public key if present (OP_DATA_33/65 followed by 33/65 bytes)

   For SegWit inputs:
   - Signatures are in the witness stack (not in scriptSig)
   - Scan ALL witness stack items for valid DER signatures
   - Handles multisig with dummy elements and non-signature items

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

open Types
open Der

(* ------------------------------------------------------------------ types *)

(* Re-export Der.parsed under the mli-declared name parsed_sig so callers
   do not need to depend on the Der module directly. *)
type parsed_sig = {
  r       : Z.t;
  s       : Z.t;
  sighash : int;
}

type signature_extraction_result = {
  input_index       : int;
  signatures        : parsed_sig list;
  public_key        : bytes option;
  script_sig        : bytes;
  witness_index     : int option;
  script_push_index : int list;
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

(* Convert Der.parsed to our public parsed_sig type *)
let parsed_sig_of_der (d : Der.parsed) : parsed_sig =
  { r = d.r; s = d.s; sighash = d.sighash }

(* ------------------------------------------------------------------ helpers *)

(* Check if bytes could be a signature candidate (has valid sighash byte) *)
let is_signature_candidate (data : bytes) =
  let len = Bytes.length data in
  if len < 8 then false
  else
    let sighash = Char.code (Bytes.get data (len - 1)) in
    match sighash with
    | 0x01 | 0x02 | 0x03 | 0x81 | 0x82 | 0x83 -> true
    | _ -> false

(* Check if an instruction is a public key push *)
let is_public_key instr =
  match instr with
  | Script.Push_data { opcode; data } ->
    let len = Bytes.length data in
    (len = 33 && opcode = 0x21) ||
    (len = 65 && opcode = 0x41)
  | _ -> false

(* ------------------------------------------------------------------ legacy input extraction *)

(* Extract all push data items from parsed script instructions.
   Returns list of (data, push_index) pairs for ALL pushes. *)
let extract_all_pushes (script : Script.t) : (bytes * int) list =
  let rec loop acc instrs idx =
    match instrs with
    | [] -> List.rev acc
    | i :: rest ->
      match i with
      | Script.Push_data { data; _ } -> loop ((data, idx) :: acc) rest (idx + 1)
      | _ -> loop acc rest (idx + 1)
  in
  loop [] script 0

(* Try to parse a push item as DER signature. Returns (parsed_sig, index) if valid. *)
let try_parse_der push =
  let (data, push_index) = push in
  match Der.of_bytes data with
  | Ok parsed -> Some (parsed_sig_of_der parsed, push_index)
  | Error _   -> None

(* Extract signatures from parsed script instructions, scanning ALL push payloads.
   Returns (signatures_with_indices, first_der_error). *)
let extract_signatures script =
  let all_pushes = extract_all_pushes script in
  let rec loop acc first_err pushes =
    match pushes with
    | [] -> (List.rev acc, first_err)
    | push :: rest ->
      match try_parse_der push with
      | Some (parsed, idx) -> loop ((parsed, idx) :: acc) first_err rest
      | None ->
        let (data, _) = push in
        if is_signature_candidate data then
          match Der.of_bytes data with
          | Ok _ -> loop acc first_err rest
          | Error err -> loop acc (Some (Invalid_der err)) rest
        else
          loop acc first_err rest
  in
  loop [] None all_pushes

(* Extract public key from parsed script instructions *)
let extract_public_key script =
  match List.find_opt is_public_key script with
  | Some (Script.Push_data { data; _ }) -> Some data
  | _ -> None

(* ------------------------------------------------------------------ legacy input *)

let extract_legacy (input_index : int) (script_sig : bytes) :
    (signature_extraction_result, error) result =
  match Parser.of_bytes script_sig with
  | Error e -> Error (Invalid_script e)
  | Ok script ->
    let (signatures_with_indices, der_error) = extract_signatures script in
    match der_error with
    | Some err -> Error err
    | None ->
      if signatures_with_indices = [] then
        Error No_signature
      else begin
        let signatures = List.map fst signatures_with_indices in
        let push_indices = List.map snd signatures_with_indices in
        let public_key = extract_public_key script in
        Ok {
          input_index;
          signatures;
          public_key;
          script_sig;
          witness_index = None;
          script_push_index = push_indices;
        }
      end

(* ------------------------------------------------------------------ SegWit input extraction *)

let extract_witness_sigs (witness_stack : bytes list) :
    (parsed_sig * int) list * (Common.Der_error.t) option =
  let rec loop acc first_err witnesses idx =
    match witnesses with
    | [] -> (List.rev acc, first_err)
    | witness :: rest ->
      match Der.of_bytes witness with
      | Ok parsed -> loop ((parsed_sig_of_der parsed, idx) :: acc) first_err rest (idx + 1)
      | Error err ->
        if is_signature_candidate witness then
          loop acc (Some err) rest (idx + 1)
        else
          loop acc first_err rest (idx + 1)
  in
  loop [] None witness_stack 0

let extract_witness_public_key witness_stack =
  match List.filter (fun w -> Bytes.length w > 0) (List.rev witness_stack) with
  | pk :: _ when Bytes.length pk = 33 || Bytes.length pk = 65 -> Some pk
  | _ -> None

(* ------------------------------------------------------------------ SegWit input *)

(* Note: script_pubkey is accepted but not used for extraction here —
   it is passed by callers for context and future script_code derivation. *)
let extract_segwit
    (input_index : int)
    (witness_stack : bytes list)
    (_script_pubkey : bytes)
  : (signature_extraction_result, error) result =
  if witness_stack = [] then
    Error No_signature
  else begin
    let (signatures_with_indices, der_error) = extract_witness_sigs witness_stack in
    match der_error with
    | Some err -> Error (Invalid_der err)
    | None ->
      if signatures_with_indices = [] then
        Error No_signature
      else begin
        let signatures = List.map fst signatures_with_indices in
        let first_witness_idx = snd (List.hd signatures_with_indices) in
        let public_key = extract_witness_public_key witness_stack in
        Ok {
          input_index;
          signatures;
          public_key;
          script_sig = Bytes.empty;
          witness_index = Some first_witness_idx;
          script_push_index = [];
        }
      end
  end

(* ------------------------------------------------------------------ public API *)

let extract (tx : Types.transaction) : (signature_extraction_result list, error) result =
  let inputs_with_idx = List.mapi (fun i inp -> (i, inp)) tx.inputs in
  let rec loop (acc : signature_extraction_result list) (pairs : (int * Types.tx_input) list) :
      (signature_extraction_result list, error) result =
    match pairs with
    | [] -> Ok (List.rev acc)
    | (input_idx, inp) :: rest ->
      let result =
        if tx.segwit then
          let witness_stack =
            match List.nth_opt tx.witnesses input_idx with
            | Some ws -> ws
            | None -> []
          in
          (* Pass the actual scriptPubKey (empty here since we don't have
             UTXO data — callers that need BIP143 script_code must supply it
             separately via extract_single or the analysis layer). *)
          extract_segwit input_idx witness_stack Bytes.empty
        else
          extract_legacy input_idx inp.script_sig
      in
      (match result with
       | Error e -> Error e
       | Ok sig_data -> loop (sig_data :: acc) rest)
  in
  loop [] inputs_with_idx

let extract_single (tx : Types.transaction) (input_index : int) :
    (signature_extraction_result, error) result =
  let n_inputs = List.length tx.inputs in
  if input_index < 0 || input_index >= n_inputs then
    Error No_signature
  else
    let inp = List.nth tx.inputs input_index in
    if tx.segwit then
      let witness_stack =
        match List.nth_opt tx.witnesses input_index with
        | Some ws -> ws
        | None -> []
      in
      extract_segwit input_index witness_stack Bytes.empty
    else
      extract_legacy input_index inp.script_sig
