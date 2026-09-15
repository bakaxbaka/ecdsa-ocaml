(** Bitcoin transaction signature extraction.

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

    {1 Example usage}

    {[
      let tx = Transaction.Parser.of_hex "01000000..." in
      match Signature_extraction.extract tx with
      | Ok sigs ->
          List.iter (fun s ->
            Printf.printf "Input %d: %d signatures\n"
              s.input_index (List.length s.signatures)
          ) sigs
      | Error e -> Printf.eprintf "Error: %s\n" (Signature_extraction.error_to_string e)
    ]}

    {1 Error handling}

    - {e Invalid_script}: Script parsing failed
    - {e Invalid_der}: DER signature parsing failed
    - {e No_signature}: Input has no signature
    - {e No_public_key}: Input has no public key (for P2PKH)
*)

(** Signature extraction result for one transaction input. *)
type t = {
  input_index : int;
  (** Index of the input in the transaction *)
  signatures  : Der.parsed list;
  (** List of DER signatures (for multi-signature inputs) *)
  public_key  : bytes option;
  (** Extracted public key, if present *)
  script_sig  : Script.t;
  (** Parsed scriptSig for debugging/analysis *)
}

(** Error types for signature extraction. *)
type error =
  | Invalid_script of Common.Parse_error.t
  | Invalid_der    of Common.Der_error.t
  | No_signature
  | No_public_key

(** Convert error to human-readable string. *)
val error_to_string : error -> string

(** [extract tx] extracts signatures from all inputs of a transaction.
    Returns [Error] on the first failure or [Ok] with a list of signature data. *)
val extract : Types.transaction -> (t list, error) result

(** [extract_single tx input_index] extracts signatures from a specific input.
    Returns [Error] if input_index is out of bounds or extraction fails. *)
val extract_single : Types.transaction -> int -> (t, error) result
