(* lib/analysis/signature/observation.ml
   Bitcoin ECDSA signature observation builder.
   
   For each transaction input this module produces a fully self-contained
   observation record that carries:
 
     - the transaction and input context (txid, input index, script type)
     - the extracted public key as a curve point
     - the extracted ECDSA signature (r, s, s_form)
     - the sighash type byte
     - the z value (message hash as a scalar) computed from the correct
       sighash algorithm for the input's script type
     - an ECDSA validity flag
     - the raw DER hex for the signature
 
   The z computation follows this routing:
 
     P2PKH / P2PK        →  Legacy.compute  (script_code = scriptPubKey of spent output)
     P2WPKH              →  Bip143.compute   (script_code = derived P2PKH equivalent)
     P2SH / P2WSH        →  not implemented (z = None, Unknown_protocol)
     Unknown / others    →  z marked as None
 
   For the three transactions under analysis all outputs are P2PKH (legacy) or
   P2WPKH (native SegWit), so both paths are fully exercised.
 
   Limitations deliberately left out of scope here:
     - P2SH redeem-script unwrapping
     - P2WSH witness-script unwrapping
     - Taproot (P2TR) key-path or script-path
     - SIGHASH_SINGLE / SIGHASH_NONE edge cases (handled by sighash layer)
 *)
 
(* Open required modules *)
open Hex
open Common
open Hash
open Field
open Scalar
open Curve
open Signature
open Verify
open Der
open Classify
open Parser
open Script
open Legacy
open Bip143
open Types
open Signature_extraction
 
(* ------------------------------------------------------------------ types *)
 
type script_type = Classify.script_type
 
(** The protocol used to compute z for this input. *)
type sighash_protocol =
  | Legacy_sighash   (** Legacy SignatureHash() algorithm *)
  | Bip143_sighash   (** BIP143 SegWit v0 digest algorithm *)
  | Unknown_protocol (** Could not determine the correct algorithm *)
 
(** Parity of the s component relative to n/2. *)
type s_form = Low_s | High_s
 
(** A fully-resolved ECDSA observation for one transaction input. *)
type observation = {
  (* -- source context ---------------------------------------------------- *)
  txid        : string;
  (** Transaction ID in display hex (reversed bytes). *)
  input_index : int;
  (** Index of this input within the transaction. *)
  script_type : script_type;
  (** Classified type of the scriptPubKey being spent. *)
  sighash_protocol : sighash_protocol;
  (** Which sighash algorithm was used to compute [z]. *)
 
  (* -- cryptographic material -------------------------------------------- *)
  public_key  : Curve.Point.t option;
  (** The spending public key as a curve point, or [None] if the raw
      bytes could not be decoded as a valid secp256k1 point. *)
  public_key_hex : string;
  (** Compressed hex of the public key (66 chars) if the point decoded successfully,
      otherwise the raw extracted pubkey hex (length varies by encoding). *)
 
  r           : Z.t;
  s           : Z.t;
  s_form      : s_form;
  sighash_type : int;
  (** The full sighash byte appended to the signature:
      0x01 = ALL, 0x02 = NONE, 0x03 = SINGLE,
      0x81 = ALL|ANYONECANPAY, 0x82 = NONE|ANYONECANPAY,
      0x83 = SINGLE|ANYONECANPAY. *)
 
  z           : Z.t option;
  (** The message hash as a big-endian integer, or [None] if the sighash
      computation could not be completed (e.g. missing UTXO value). *)
 
  (* -- verification ------------------------------------------------------- *)
  ecdsa_valid : bool option;
  (** [Some true]  — signature verified against [public_key] and [z].
      [Some false] — verification failed.
      [None]       — could not verify (missing key or missing z). *)
 
  (* -- raw data ----------------------------------------------------------- *)
  raw_der_hex : string;
  (** Canonical DER encoding of (r, s), with the sighash byte appended,
      as lowercase hex. May differ byte-for-byte from the original
      on-chain signature if that was non-canonical. *)
}
 
(** Error type for observation building. *)
type error =
  | Extraction_error of Signature_extraction.error
  | No_signatures
  | Der_to_signature of string   (* Signature.make failure message *)
 
let error_to_string = function
  | Extraction_error e -> Signature_extraction.error_to_string e
  | No_signatures      -> "No signatures found"
  | Der_to_signature m -> Printf.sprintf "Signature construction failed: %s" m
 
(* ------------------------------------------------------------------ DER encoding *)
 
(** Encode a Z.t value as minimal-length big-endian bytes (no leading zero unless needed) *)
let z_to_minimal_bytes (z : Z.t) : bytes =
  if Z.equal z Z.zero then Bytes.make 1 '\x00'
  else
    let hex_str = Z.format "%x" z in
    let hex_str = if String.length hex_str mod 2 = 1 then "0" ^ hex_str else hex_str in
    let byte_count = String.length hex_str / 2 in
    let b = Bytes.create byte_count in
    for i = 0 to byte_count - 1 do
      let hex_pair = String.sub hex_str (i * 2) 2 in
      Bytes.set b i (Char.chr (int_of_string ("0x" ^ hex_pair)))
    done;
    (* If high bit is set, prepend 0x00 to keep it positive in DER *)
    if Char.code (Bytes.get b 0) land 0x80 <> 0 then
      let b' = Bytes.create (byte_count + 1) in
      Bytes.set b' 0 '\x00';
      Bytes.blit b 0 b' 1 byte_count;
      b'
    else b
 
(** Encode ECDSA signature (r, s, sighash) as DER with sighash byte appended *)
let encode_der_signature (r : Z.t) (s : Z.t) (sighash : int) : string =
  let r_bytes = z_to_minimal_bytes r in
  let s_bytes = z_to_minimal_bytes s in
  let r_len = Bytes.length r_bytes in
  let s_len = Bytes.length s_bytes in
  (* DER: 30 <total_len> 02 <r_len> <r> 02 <s_len> <s> *)
  let total_len = 2 + r_len + 2 + s_len in  (* two 02 tags and two length bytes *)
  let der = Bytes.create (1 + 1 + total_len + 1) in  (* 30, len, content, sighash *)
  Bytes.set der 0 '\x30';
  Bytes.set der 1 (Char.chr total_len);
  Bytes.set der 2 '\x02';
  Bytes.set der 3 (Char.chr r_len);
  Bytes.blit r_bytes 0 der 4 r_len;
  let s_offset = 4 + r_len in
  Bytes.set der s_offset '\x02';
  Bytes.set der (s_offset + 1) (Char.chr s_len);
  Bytes.blit s_bytes 0 der (s_offset + 2) s_len;
  let sighash_offset = s_offset + 2 + s_len in
  Bytes.set der sighash_offset (Char.chr sighash);
  Hex.of_bytes der
 
(* Big-endian bytes → Z.t (same as Verify.z_of_bytes) *)
let z_of_bytes (b : bytes) : Z.t =
  let len = Bytes.length b in
  let acc = ref Z.zero in
  for i = 0 to len - 1 do
    acc := Z.add (Z.shift_left !acc 8)
                  (Z.of_int (Char.code (Bytes.get b i)))
  done;
  !acc
 
(* Hex-encode bytes as lowercase string *)
let bytes_to_hex (b : bytes) : string =
  Hex.of_bytes b
 
(* Compute RIPEMD160(SHA256(data)) — used for Bitcoin address hashing *)
let hash160 (b : bytes) : bytes =
  Digestif.RMD160.(
    digest_bytes (Hash.sha256 b) |> to_raw_string |> Bytes.of_string)
 
(* Build script_code for legacy scripts, preferring spk_hint when available.
   For P2PKH: reconstructs scriptPubKey from pubkey if spk_hint is None.
   For P2PK: always uses pubkey to build correct scriptPubKey.
   This allows callers to provide the actual spent output's scriptPubKey
   via spk_hint, which takes precedence over reconstruction. *)
let p2pkh_script_code_from_pubkey (pubkey_bytes : bytes) : bytes =
  let h160 = hash160 pubkey_bytes in
  let sc = Bytes.create 25 in
  Bytes.set sc 0 '\x76'; Bytes.set sc 1 '\xa9'; Bytes.set sc 2 '\x14';
  Bytes.blit h160 0 sc 3 20;
  Bytes.set sc 23 '\x88'; Bytes.set sc 24 '\xac';
  sc
 
let script_code_legacy (spk_hint : bytes option) (pubkey_bytes : bytes) : bytes =
  match spk_hint with
  | Some spk -> spk        (* Use the actual spent scriptPubKey if available *)
  | None -> p2pkh_script_code_from_pubkey pubkey_bytes  (* Reconstruct from pubkey *)
 
(* Try to decode a raw public key (33 or 65 bytes) to a curve point *)
let decode_pubkey (raw : bytes) : Curve.Point.t option =
  let hex = bytes_to_hex raw in
  let len = Bytes.length raw in
  let result =
    if len = 33 then Curve.Point.of_compressed hex
    else if len = 65 then Curve.Point.of_uncompressed hex
    else Error (Common.Parse_error.Bad_length "pubkey")
  in
  match result with
  | Ok pt -> Some pt
  | Error _ -> None
 
(* Determine s_form for a Z.t value of s *)
let classify_s_form (s : Z.t) : s_form =
  (* n/2 for secp256k1: floor(n/2) where n = ...CD0364141
     n/2 = ...5D576E7357A4501DDFE92F46681B20A0 *)
  let n_half = Z.of_string
    "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0" in
  if Z.compare s n_half <= 0 then Low_s else High_s
 
(* Classify the script type from a spent output's scriptPubKey.
   For legacy txs the scriptPubKey comes from the *previous* output, which we
   do not have in-transaction.  We instead classify from the first output's
   scriptPubKey if the tx is legacy (heuristic acceptable for our three txs
   whose inputs are all P2PKH with the same script pattern), or from the
   actual spending witness for SegWit. *)
let classify_from_tx (tx : Types.transaction) (input_index : int)
    (spk_hint : bytes option) : script_type =
  (* Prefer an explicit hint (the actual scriptPubKey of the spent UTXO). *)
  match spk_hint with
  | Some spk -> Classify.of_script_pubkey spk
  | None ->
    (* Heuristic: look at the scriptSig / witness to infer type.
       - Non-empty witness → SegWit (P2WPKH or P2WSH)
       - Non-empty scriptSig with a push of length 33/65 at the end → P2PKH *)
    let inp = List.nth tx.inputs input_index in
    if tx.segwit then begin
      match List.nth_opt tx.witnesses input_index with
      | Some ws when List.length ws = 2 ->
        (* P2WPKH witness: [sig; pubkey] *)
        let last = List.nth ws (List.length ws - 1) in
        if Bytes.length last = 33 || Bytes.length last = 65 then Classify.P2WPKH
        else Classify.P2WSH
      | Some _ -> Classify.Unknown
      | None -> Classify.Unknown
    end else begin
      (* Legacy: try to parse scriptSig and look at trailing push size *)
      match Parser.of_bytes inp.script_sig with
      | Error _ -> Classify.Unknown
      | Ok instrs ->
        (* Standard P2PKH scriptSig ends with a compressed/uncompressed pubkey push *)
        let pushes = List.filter_map (function
          | Script.Push_data { data; _ } -> Some data
          | _ -> None) instrs
        in
        match List.rev pushes with
        | pk :: _ when (Bytes.length pk = 33 || Bytes.length pk = 65)
                      && decode_pubkey pk <> None ->
          (* Looks like a P2PKH scriptSig with a valid curve point *)
          Classify.P2PKH
        | _ -> Classify.Unknown
    end
 
(* ------------------------------------------------------------------ sighash routing *)
 
(* Build script_code for legacy P2PKH.
   For a P2PKH input, the script_code is the scriptPubKey of the spent output:
     OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG
   We reconstruct it from the extracted public key via Hash160. *)
let p2pkh_script_code_from_pubkey (pubkey_bytes : bytes) : bytes =
  let hash160_bytes = hash160 pubkey_bytes in
  let sc = Bytes.create 25 in
  Bytes.set sc 0  '\x76';
  Bytes.set sc 1  '\xa9';
  Bytes.set sc 2  '\x14';
  Bytes.blit hash160_bytes 0 sc 3 20;
  Bytes.set sc 23 '\x88';
  Bytes.set sc 24 '\xac';
  sc
 
(* Build script_code for legacy P2PK.
   For a P2PK input, the script_code is the scriptPubKey of the spent output:
     <pubkey push> OP_CHECKSIG
   i.e. 21 <33-byte pubkey> ac for compressed, or 41 <65-byte pubkey> ac for uncompressed *)
let p2pk_script_code_from_pubkey (pubkey_bytes : bytes) : bytes =
  let n = Bytes.length pubkey_bytes in
  let sc = Bytes.create (n + 2) in
  Bytes.set sc 0 (Char.chr n);        (* direct push of n bytes *)
  Bytes.blit pubkey_bytes 0 sc 1 n;
  Bytes.set sc (n + 1) '\xac';        (* OP_CHECKSIG *)
  sc
 
(* Compute z for a P2WPKH input (BIP143).
   script_code = OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG
   derived from the witness program in the scriptPubKey.
   value = satoshi value of the spent UTXO (required by BIP143). *)
let compute_z_p2wpkh (tx : Types.transaction) (input_index : int)
    (script_code : bytes) (value : Int64.t) (sighash_type : int) : bytes option =
  match Bip143.compute tx input_index script_code value sighash_type with
  | Ok hash_bytes -> Some hash_bytes
  | Error _ -> None
 
(* ------------------------------------------------------------------ observation builder *)
 
(** [build_observation tx txid input_index spk_hint utxo_value_hint]
    constructs one observation for the input at [input_index].
 
    [spk_hint]        — the scriptPubKey of the spent UTXO, if known.
                        When [None] the type is inferred heuristically.
    [utxo_value_hint] — satoshi value of the spent UTXO, required for
                        BIP143 (P2WPKH) z computation.  When [None]
                        for a P2WPKH input, z will be [None].
 *)
let build_observation
    (tx           : Types.transaction)
    (txid         : string)
    (input_index  : int)
    (spk_hint     : bytes option)
    (utxo_value   : Int64.t option)
  : (observation, error) result =
 
  (* 1. Extract signature and public key from this input. *)
  let extraction =
    match Signature_extraction.extract_single tx input_index with
    | Error e -> Error (Extraction_error e)
    | Ok r    -> Ok r
  in
  match extraction with
  | Error e -> Error e
  | Ok ex ->
    match ex.signatures with
    | [] -> Error No_signatures
    (* Use the first signature for single-sig inputs (P2PKH, P2WPKH). *)
    | psig :: _ ->
      (* 2. Construct Signature.t to get s_form and validated scalars. *)
      let sig_result = Signature.make psig.r psig.s in
      match sig_result with
      | Error msg -> Error (Der_to_signature msg)
      | Ok sig' ->
        (* sig' is the validated Signature.t used for verification in step 7 *)
 
        (* 3. Decode public key to a curve point. *)
        let (pubkey_pt, pubkey_hex) =
          match ex.public_key with
          | None -> (None, "")
          | Some raw ->
            let pt = decode_pubkey raw in
            let hex = match pt with
              | Some point -> Curve.Point.to_compressed point
              | None -> bytes_to_hex raw  (* Fall back to raw if point decoding failed *)
            in
            (pt, hex)
        in
 
        (* 4. Classify the script type. *)
        let stype = classify_from_tx tx input_index spk_hint in
 
        (* 5. Compute z using the appropriate sighash algorithm. *)
        let (z_bytes_opt, protocol) =
          match stype with
          | Classify.P2PK ->
            let zb =
              match ex.public_key with
              | None -> None
              | Some pk_bytes ->
                let sc = p2pk_script_code_from_pubkey pk_bytes in
                match Legacy.compute tx input_index sc psig.sighash with
                | Ok h -> Some h | Error _ -> None
            in
            (zb, Legacy_sighash)
 
          | Classify.P2PKH ->
            let zb =
              match ex.public_key with
              | None -> None
              | Some pk_bytes ->
                let sc = script_code_legacy spk_hint pk_bytes in
                match Legacy.compute tx input_index sc psig.sighash with
                | Ok h -> Some h | Error _ -> None
            in
            (zb, Legacy_sighash)
 
          | Classify.P2WPKH ->
            (* For P2WPKH, the script_code is OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG
               (same as legacy P2PKH script_code), which we can build directly from the pubkey. *)
            let sc_opt =
              match spk_hint with
              | Some spk -> 
                (* BIP143 defines P2WPKH script_code as P2PKH form (25 bytes).
                   Classify.script_code_for_p2wpkh returns this, not the witness program. *)
                Classify.script_code_for_p2wpkh spk
              | None ->
                (* Derive script_code directly from pubkey *)
                match ex.public_key with
                | None -> None
                | Some pk_bytes -> Some (p2pkh_script_code_from_pubkey pk_bytes)
            in
            (match sc_opt, utxo_value with
             | Some sc, Some value ->
               (compute_z_p2wpkh tx input_index sc value psig.sighash,
                Bip143_sighash)
             | _ ->
               (None, Bip143_sighash))
 
          | Classify.P2SH ->
            (* P2SH: the redeem script is in the scriptSig, but for a
               standard P2SH-P2WPKH we'd need the redeemScript.
               For bare P2SH legacy signing, use Legacy.compute with
               the redeemScript as script_code.  Not implemented here
               because our target transactions are not P2SH. *)
            (None, Unknown_protocol)
 
          | _ ->
            (None, Unknown_protocol)
        in
 
        (* 6. Convert z bytes to scalar. *)
        let z_opt = Option.map z_of_bytes z_bytes_opt in
 
        (* 7. ECDSA verification. *)
        let ecdsa_valid =
          match pubkey_pt, z_bytes_opt with
          | Some pk, Some zb ->
            Some (Verify.verify_bytes ~pubkey:pk ~hash_bytes:zb sig')
          | _ -> None
        in
 
        (* 8. Build the raw DER hex.  Re-serialize from r, s, sighash as proper DER format *)
        let raw_der_hex = encode_der_signature psig.r psig.s psig.sighash in
 
        let s_form = classify_s_form psig.s in
 
        Ok {
          txid;
          input_index;
          script_type  = stype;
          sighash_protocol = protocol;
          public_key   = pubkey_pt;
          public_key_hex = pubkey_hex;
          r            = psig.r;
          s            = psig.s;
          s_form;
          sighash_type = psig.sighash;
          z            = z_opt;
          ecdsa_valid;
          raw_der_hex;
        }
 
(** [build_all tx txid spk_hints utxo_values] builds one observation per
    input.  [spk_hints] and [utxo_values] are indexed by input index;
    use [None] elements for unknown values.
 
    Returns a list of [(input_index, result)] so callers can report
    per-input errors without aborting the whole analysis. *)
let build_all
    (tx          : Types.transaction)
    (txid        : string)
    (spk_hints   : bytes option list)
    (utxo_values : Int64.t option list)
  : (int * (observation, error) result) list =
  let n = List.length tx.inputs in
  List.init n (fun i ->
    let spk   = List.nth_opt spk_hints   i |> Option.join in
    let value = List.nth_opt utxo_values i |> Option.join in
    (i, build_observation tx txid i spk value)
  )
