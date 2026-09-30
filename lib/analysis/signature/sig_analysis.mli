(** Signature pattern analysis and cryptographic relationship detection.

    Analyzes patterns in signature components (r, s, z) to identify
    vulnerabilities. The main vulnerability is nonce reuse: same [r]
    across different messages, which allows private key recovery.

    {b Important:} This module now correctly identifies:
    - {e Nonce reuse} (same r, different z): THE REAL VULNERABILITY
    - Invalid signatures (z=0, r=0, s=0) are filtered
    - Key recovery is attempted when possible

    The old "same z, different r" analysis was incorrect - signing
    the same message with different nonces is normal and safe.
*)

(** A single signature record with all components *)
type signature_record = {
  tx_id : string;              (** Transaction hash *)
  input_index : int;           (** Which input in the transaction *)
  pubkey : string option;      (** Public key that signed, if known. Not populated from CSV; use externally *)
  r : Z.t;                     (** r component of signature *)
  s : Z.t;                     (** s component of signature *)
  z : Z.t option;              (** Message hash (SIGHASH), None if unknown *)
  timestamp : string option;   (** When extracted, if known. Not populated from CSV; reserved for external use *)
}

(** Result of pattern analysis *)
type analysis_result = {
  signatures : signature_record list;    (** Valid, deduplicated signatures *)
  repeated_r : (Z.t * signature_record list) list;  (** Nonce reuse: same r, different z *)
  invalid : signature_record list;       (** Signatures with z=0, r=0, or s=0 *)
}

(** Count occurrences of each value in [lst], keeping only values seen more
    than once.  The result is sorted by value so that repeated runs over the
    same input produce byte-identical output. *)
val count_occurrences : Z.t list -> (Z.t * int) list

(** Analyze signatures for cryptographic vulnerabilities.
    Returns valid signatures and any nonce reuse patterns found. *)
val analyze : signature_record list -> analysis_result

(** Print analysis results to stdout *)
val print_analysis : analysis_result -> unit

(** Format a z value as 64-char lowercase hex *)
val format_z_hex : Z.t -> string

(** Format a z value as hex, handling None *)
val format_z_hex_opt : Z.t option -> string

(** Format an r value as 64-char lowercase hex *)
val format_r_hex : Z.t -> string

(** Load signatures from a CSV file.
    Expected format: txid,input_index,r,s,z,sighash (6 fields)
    
    Parsing rules:
    - r, s: parsed as hex (with or without 0x prefix), validated as in [1, n)
    - z: parsed as hex, or None if empty, "NONE", or contains placeholder (_)
    - z=0 is rejected (invalid in ECDSA)
    - Rows with invalid r/s are skipped
    - sighash field (index 5) is currently ignored; pubkey is set to None
    
    Limitations:
    - If z is "NEEDS_PROPER_SIGHASH" (from the extractor), those rows load
      but cannot contribute to key recovery (recovery needs real z).
    - Actual z requires transaction sighash calculation. *)
val load_csv : string -> signature_record list

(** Attempt to recover private keys from nonce-reuse signatures.
    
    Requires: same r in multiple signatures with different z values.
    
    Formula:
      k = (z₁ - z₂) · (s₁ - s₂)⁻¹  mod n
      d = (s₁ · k - z₁) · r⁻¹      mod n
    
    Returns: list of (private_key, sig1, sig2) for each recoverable case.
    
    Important:
    - Recovered k may be k or n-k (both satisfy r = (k·G).x mod n).
    - Validate against pubkey (if available) to confirm the key.
    - Skips pairs with equal z (those are duplicates, not nonce reuse). *)
val recover_private_keys : signature_record list -> (Z.t * signature_record * signature_record) list
