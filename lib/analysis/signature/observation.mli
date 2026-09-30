(** Bitcoin ECDSA signature observation builder.

    Combines transaction parsing, signature extraction, script classification,
    sighash computation, and ECDSA verification into a single self-contained
    observation record per transaction input.

    {1 Sighash routing}

    {v
      P2PKH / P2PK        →  Legacy.compute   (script_code reconstructed from pubkey)
      P2WPKH              →  Bip143.compute   (script_code derived from witness program)
      P2SH / P2WSH        →  not implemented (returns z = None, Unknown_protocol)
      Unknown / others    →  z = None
    v}

    {1 Example}

    {[
      let tx   = Transaction.Parser.of_hex raw_hex |> Result.get_ok in
      let txid = "d33ade0feef46c87..." in
      match Observation.build_observation tx txid 0 None None with
      | Ok obs ->
        Printf.printf "r = %s\n" (Z.to_string obs.r);
        Printf.printf "valid = %b\n" (Option.value ~default:false obs.ecdsa_valid)
      | Error e ->
        Printf.eprintf "error: %s\n" (Observation.error_to_string e)
    ]}
*)

type script_type = Classify.script_type

(** Which sighash algorithm was used to produce [z]. *)
type sighash_protocol =
  | Legacy_sighash
  | Bip143_sighash
  | Unknown_protocol

(** Parity of the s component relative to n/2. *)
type s_form = Low_s | High_s

(** A fully resolved ECDSA observation for one transaction input. *)
type observation = {
  txid             : string;
  (** Transaction ID in display hex (reversed bytes). *)
  input_index      : int;
  (** Index of this input within the transaction. *)
  script_type      : script_type;
  (** Classified type of the scriptPubKey being spent. *)
  sighash_protocol : sighash_protocol;
  (** Which sighash algorithm was used to compute [z]. *)
  public_key       : Curve.Point.t option;
  (** The spending public key as a curve point, or [None] if the raw bytes
      could not be decoded as a valid secp256k1 point. *)
  public_key_hex   : string;
  (** Compressed hex of the public key (66 chars) if the point decoded successfully,
      otherwise the raw extracted pubkey hex (length varies by encoding). *)
  r                : Z.t;
  (** r component of signature *)
  s                : Z.t;
  (** s component of signature *)
  s_form           : s_form;
  (** Parity of s relative to n/2. *)
  sighash_type     : int;
  (** The full sighash byte appended to the signature:
      0x01 = ALL, 0x02 = NONE, 0x03 = SINGLE,
      0x81 = ALL|ANYONECANPAY, 0x82 = NONE|ANYONECANPAY,
      0x83 = SINGLE|ANYONECANPAY. *)
  z                : Z.t option;
  (** The message hash as a big-endian integer, or [None] if the sighash
      computation could not be completed (e.g. missing UTXO value). *)
  ecdsa_valid      : bool option;
  (** [Some true]  — signature verified against [public_key] and [z].
      [Some false] — verification failed.
      [None]       — could not verify (missing key or missing z). *)
  raw_der_hex      : string;
  (** Canonical DER encoding of (r, s), with the sighash byte appended,
      as lowercase hex. May differ byte-for-byte from the original
      on-chain signature if that was non-canonical. *)
}

type error =
  | Extraction_error of Signature_extraction.error
  | No_signatures
  | Der_to_signature of string

val error_to_string : error -> string

(** [build_observation tx txid input_index spk_hint utxo_value] builds
    a single observation for the given input.

    [spk_hint]   — scriptPubKey of the spent UTXO, if available.
    [utxo_value] — satoshi value of the spent UTXO (required for BIP143). *)
val build_observation :
  Types.transaction ->
  string ->
  int ->
  bytes option ->
  Int64.t option ->
  (observation, error) result

(** [build_all tx txid spk_hints utxo_values] builds one observation per
    input.  Returns [(input_index, result)] for every input so per-input
    failures are visible without aborting. *)
val build_all :
  Types.transaction ->
  string ->
  bytes option list ->
  Int64.t option list ->
  (int * (observation, error) result) list
