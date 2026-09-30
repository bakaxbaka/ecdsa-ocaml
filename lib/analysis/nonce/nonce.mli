(** Bitcoin ECDSA nonce relationship analysis.

    SECURITY CRITICAL MODULE: This module detects nonce reuse vulnerabilities
    that allow private key recovery from ECDSA signatures.

    {1 Nonce Reuse Detection}

    Detects when two signatures reuse the same ephemeral key (nonce):
      - Case 1: Same nonce k1 = k2
      - Case 2: Opposite nonce k1 ≡ -k2 (mod n)

    Both cases allow recovery of a private key candidate via the formula:
      d ≡ r^-1 (k·s1 - z1)  (mod n)
    where k is recovered from (z1 - z2) / (s1 - s2) or (z1 - z2) / (s1 + s2).

    {2 Important Caveats}

    - The recovered private key is a CANDIDATE that MUST be verified against
      the public key via point multiplication.
    - Requires z1 ≠ z2 (different message hashes).
    - Astronomically rare: s1 - s2 ≡ 0 and s1 + s2 ≡ 0 (mod n) simultaneously.

    {1 What Is NOT Implemented}

    The following advertised features are NOT implemented pending real
    cryptographic implementation:

    - {b Hidden Number Problem (HNP) lattice construction}
    - {b Lattice basis reduction (LLL/BKZ)}
    - {b Bit-similarity metrics} (cryptographically meaningless)

    The functions [detect_hnp_attack] and [detect_lattice_attack] always
    return [[]] (empty list). Do not emit false positives on transactions
    with multiple inputs.

    {1 Cryptographic Facts}

    r = x(k·G) mod n is a nonlinear function of k. Two different nonces
    produce r values essentially uniformly distributed over [0, n).

    Bit similarity, Hamming distance, or leading-bit agreement between
    r values do NOT indicate related nonces or exploitable structure.

    The ONLY meaningful relationship is exact equality (Same_nonce).

    {1 Example}

    {[
      let obs1 = ... (* observation 1 *)
      let obs2 = ... (* observation 2 *)
      let analysis = Nonce.analyze_input "txid" 0 [obs1; obs2] in
      match analysis.risk_level with
      | "CRITICAL" ->
        Printf.printf "Nonce reuse detected: %s\n" analysis.summary
      | _ ->
        Printf.printf "No nonce reuse: %s\n" analysis.summary
    ]}
*)

(** Result of HNP analysis (PLACEHOLDER) *)
type hnp_result = {
  leaked_bits : int;           (** NOTE: Always 0; HNP not implemented *)
  bound : Z.t;                 (** NOTE: Always curve_order *)
  hnp_difficulty : float;      (** NOTE: Always 256.0 *)
  confidence : float;          (** NOTE: Always 0.0 *)
}

(** Possible nonce relationships between two signatures *)
type nonce_relationship =
  | Unrelated                  (** No cryptographically meaningful relationship *)
  | Same_nonce of Z.t          (** Same r value: k1=k2 or k1=-k2 (mod n) *)
  | Related_nonce of {
      r1 : Z.t;
      r2 : Z.t;
      z1 : Z.t;
      z2 : Z.t;
      similarity : float;      (** UNUSED: kept for type compatibility *)
    }
  | HNP_candidate of {
      r_values : Z.t list;
      z_values : Z.t list;
      hnp : hnp_result;
    }

(** Detected cryptographic attack vector *)
type attack_vector =
  | Nonce_reuse of {
      r : Z.t;
      s1 : Z.t;
      s2 : Z.t;
      z1 : Z.t;
      z2 : Z.t;
      private_key : Z.t;       (** Recovered private key CANDIDATE *)
    }
  | HNP_partial of {
      leaked_bits : int;
      observations : Analysis_signature.Observation.observation list;
      hnp : hnp_result;
    }
  | Lattice_candidate of {
      n_equations : int;
      lattice_rank : int;
      observations : Analysis_signature.Observation.observation list;
    }
  | No_attack

(** Result of analyzing a single transaction input *)
type input_analysis = {
  txid : string;
  input_index : int;
  relationships : nonce_relationship list;
  attack_vectors : attack_vector list;
  risk_score : float;          (** 0.0 = safe, 1.0 = critical *)
  risk_level : string;         (** "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE" *)
  summary : string;
}

(** Analyze observations from a transaction input for nonce vulnerabilities.
    
    Detects:
    - Nonce reuse (same r, allowing private key recovery)
    - Computes both k1=k2 and k1=-k2 cases
    
    Does NOT detect (pending implementation):
    - HNP lattice attacks
    - Lattice basis reduction attacks
*)
val analyze_input :
  string ->
  int ->
  Analysis_signature.Observation.observation list ->
  input_analysis

(** Analyze all inputs in a transaction *)
val analyze_transaction :
  string ->
  Analysis_signature.Observation.observation list list ->
  input_analysis list

(** Classify the cryptographic relationship between exactly two observations.
    This is the pairwise primitive underlying {!analyze_input}. *)
val analyze_pair :
  Analysis_signature.Observation.observation ->
  Analysis_signature.Observation.observation ->
  nonce_relationship

(** Format analysis result for display *)
val format_result : input_analysis -> string

(** Format nonce relationship for display *)
val format_nonce_relationship : nonce_relationship -> string

(** Format attack vector for display *)
val format_attack_vector : attack_vector -> string

(** {1 Recovery Details}

    Private key recovery from nonce reuse follows the ECDSA algebra:

    {v
    s1 ≡ k^-1 (z1 + r·d) (mod n)
    s2 ≡ k^-1 (z2 + r·d) (mod n)
    v}

    Case 1: k1 = k2
    {v
    s1 - s2 ≡ k^-1 (z1 - z2)
    k ≡ (z1 - z2) / (s1 - s2)
    d ≡ r^-1 (k·s1 - z1)
    v}

    Case 2: k1 ≡ -k2 (mod n)
    {v
    s1 + s2 ≡ k^-1 (z1 - z2)
    k ≡ (z1 - z2) / (s1 + s2)
    d ≡ r^-1 (k·s1 - z1)
    v}

    Both cases use the same formula for d. The function attempts both
    (s1 - s2) and (s1 + s2) inversions.
*)
