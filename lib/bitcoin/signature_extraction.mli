(** Bitcoin transaction signature extraction.

    Parses transaction inputs to extract ECDSA signatures from scriptSigs
    (legacy inputs) and witness stacks (SegWit inputs).

    {1 Extraction workflow}

    For legacy inputs (segwit=false or empty witness):
    - Parse scriptSig using {!Script.Parser.of_bytes}
    - Scan every pushed item for strict DER-encoded signatures
    - Parse DER signatures using {!Der.of_bytes}
    - Extract public key if present (33- or 65-byte push)

    For SegWit inputs (non-empty witness stack):
    - Signatures are in the witness stack items, not in the scriptSig
    - Public key is the last non-empty item of length 33 or 65

    {1 Malformed candidate policy}

    When a push payload looks like a signature candidate (valid sighash byte,
    length ≥ 8) but fails strict DER parsing, [Invalid_der] is returned
    rather than silently skipping it.  This makes parse failures explicit.

    {1 Error handling}

    - {e Invalid_script}: scriptSig could not be parsed as a Script
    - {e Invalid_der}: a candidate signature failed strict DER validation
    - {e No_signature}: the input contains no recognisable signature
    - {e No_public_key}: the input contains no recognisable public key
*)

(** A single parsed DER signature with its sighash byte.
    [r] and [s] are the raw [Z.t] integers before range-checking against [n].
    Range validation is performed by {!Signature.make}. *)
type parsed_sig = {
  r       : Z.t;
  s       : Z.t;
  sighash : int;
}

(** Signature extraction result for one transaction input. *)
type signature_extraction_result = {
  input_index       : int;
  (** Index of this input in the transaction. *)
  signatures        : parsed_sig list;
  (** All DER-decoded signatures found in this input.
      Typically one for P2PKH/P2WPKH, more for multisig. *)
  public_key        : bytes option;
  (** Extracted public key bytes (33 bytes compressed or 65 bytes
      uncompressed), if present. [None] for multisig or bare P2PK inputs
      where the key is in the scriptPubKey, not the scriptSig. *)
  script_sig        : bytes;
  (** Raw scriptSig bytes (empty for pure SegWit inputs). *)
  witness_index     : int option;
  (** Witness stack index of the first signature, when extracted from
      the witness.  [None] for legacy inputs. *)
  script_push_index : int list;
  (** Script push indices where signatures were found, for legacy inputs.
      Empty for SegWit inputs. *)
}

(** Error type for signature extraction failures. *)
type error =
  | Invalid_script of Common.Parse_error.t
  | Invalid_der    of Common.Der_error.t
  | No_signature
  | No_public_key

(** [error_to_string e] returns a human-readable description of [e]. *)
val error_to_string : error -> string

(** [extract tx] extracts signatures from all inputs of [tx].
    Returns [Ok results] where [results] has one entry per input,
    or [Error] on the first failure encountered. *)
val extract :
  Types.transaction ->
  (signature_extraction_result list, error) result

(** [extract_single tx input_index] extracts signatures from one specific
    input.  Returns [Error No_signature] if [input_index] is out of bounds. *)
val extract_single :
  Types.transaction ->
  int ->
  (signature_extraction_result, error) result
