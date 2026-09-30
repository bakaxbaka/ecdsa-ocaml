(* lib/analysis/types/signature_types.ml
   Core types for signature analysis: context, observation, and nonce equivalence. *)

type curve = Secp256k1

type protocol =
  | Bitcoin_legacy   (* Legacy P2PKH/P2SH signatures *)
  | Bitcoin_segwit   (* BIP143 SegWit v0 signatures *)
  | Generic          (* Generic ECDSA context *)

type domain = {
  chain_id : int;          (* For EVM chains, 0 for Bitcoin *)
  fork_id : int;           (* Fork identifier for hard forks *)
}

type signing_context = {
  curve : curve;
  protocol : protocol;
  domain : domain;
  message_hash : Scalar.t; (* The message hash that was signed *)
}

(* S-form classification *)
type s_form = Low_s | High_s

(* Quality rating for observations *)
type quality = High | Medium | Low

(* S-form before normalization for observation *)
type original_s_form = Original of s_form | Unknown_form

(* Public key type placeholder - will be defined in crypto module *)
type public_key = Scalar.t (* Simplified: in practice this would be Point.t *)

(* Signature observation with context and metadata *)
type observation = {
  signature : Signature.t;
  original_s_form : original_s_form; (* S-form before any normalization *)
  context : signing_context;
  public_key : public_key option; (* Known public key if available *)
  quality : quality; (* Confidence level of this observation *)
  raw_der : string option; (* Original DER encoding if available *)
  witness_index : int option; (* Witness stack index for SegWit *)
  script_push_index : int option; (* Script push index for legacy *)
}

(* Nonce equivalence relationship between two observations *)
type nonce_equivalence =
  | Same_nonce        (* Same nonce k was used for both signatures *)
  | Negated_nonce     (* Nonces are negations: k1 = -k2 mod n *)
  | Unknown           (* Cannot determine relationship *)
  | Different_nonce   (* Different nonces (no known relationship) *)

(* Finding types for anomaly detection *)
type finding_type =
  | Reused_nonce          (* Same nonce used across signatures *)
  | Known_nonce_exploit   (* Nonce k is known, key can be computed *)
  | Algebraic_consistency (* Algebraic relationship between signatures *)
  | Context_collision     (* Different protocols with same (r, s) *)
  | Potential_key_leak    (* Multiple signatures with reused r but different messages *)
  | Low_s_mismatch        (* Expected low-S but high-S signature found *)
  | Malformed_signature   (* Signature fails verification *)
  | Invalid_public_key    (* Recovered public key doesn't match expected *)
  | Unknown_anomaly       (* Unknown anomaly detected *)

type finding_severity = Critical | High | Medium | Low

type finding = {
  finding_type : finding_type;
  severity : finding_severity;
  observations : observation list; (* All observations involved in this finding *)
  evidence : string; (* Human-readable explanation *)
  confidence : float; (* 0.0 to 1.0 *)
  timestamp : int64; (* Unix timestamp when finding was created *)
}

(* Upgrade Potential finding to Confirmed based on algebraic consistency *)
let upgrade_to_confirmed finding =
  { finding with severity = Critical; confidence = 1.0 }

(* Downgrade finding if evidence weakens *)
let downgrade_if_inconsistent finding reason =
  { finding with severity = Low; evidence = finding.evidence ^ "; " ^ reason; confidence = 0.3 }
