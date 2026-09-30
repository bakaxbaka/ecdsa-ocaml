(* lib/analysis/nonce/nonce.ml
   Bitcoin ECDSA nonce relationship analysis engine.
   
   SECURITY CRITICAL: This module detects nonce reuse vulnerabilities
   that allow private key recovery. All computations are cryptographically
   sensitive and must be verified carefully.
   
   Implemented:
     1. Nonce reuse detection (same r → private key recovery possible)
     2L. Both cases: k1 = k2 and k1 = -k2 (mod n)
     3. Proper modular arithmetic with Euclidean remainder
     4. Conservative risk scoring
   
   NOT implemented (intentionally disabled pending real implementation):
     - Hidden Number Problem lattice construction
     - Lattice basis reduction (LLL/BKZ)
     - Bit similarity metrics (cryptographically meaningless)
 *)
 
open Analysis_signature.Observation
 
type hnp_result = {
  leaked_bits : int;           (** NOTE: Placeholder, not computed *)
  bound : Z.t;                 (** NOTE: Placeholder, not computed *)
  hnp_difficulty : float;      (** NOTE: Placeholder, not computed *)
  confidence : float;          (** NOTE: Placeholder, not computed *)
}
 
type nonce_relationship =
  | Unrelated                  (** No cryptographically meaningful relationship *)
  | Same_nonce of Z.t          (** Same r value: either k1=k2 or k1=-k2 (mod n) *)
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
 
type attack_vector =
  | Nonce_reuse of {
      r : Z.t;
      s1 : Z.t;
      s2 : Z.t;
      z1 : Z.t;
      z2 : Z.t;
      private_key : Z.t;       (** Recovered private key candidate *)
    }
  | HNP_partial of {
      leaked_bits : int;
      observations : observation list;
      hnp : hnp_result;
    }
  | Lattice_candidate of {
      n_equations : int;
      lattice_rank : int;
      observations : observation list;
    }
  | No_attack
 
type input_analysis = {
  txid : string;
  input_index : int;
  relationships : nonce_relationship list;
  attack_vectors : attack_vector list;
  risk_score : float;          (** 0.0 = safe, 1.0 = critical *)
  risk_level : string;         (** "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE" *)
  summary : string;
}
 
(* ------------------------------------------------------------------ constants *)
 
let curve_order = Scalar.modulus
let bit_length_n = 256  (* secp256k1 order is 256-bit *)
 
(* ------------------------------------------------------------------ modular arithmetic *)
 
let mod_sub (a : Z.t) (b : Z.t) : Z.t =
  let r = Z.sub a b in
  if Z.sign r < 0 then Z.add r curve_order else r
 
(** Use Euclidean remainder to ensure result is always non-negative *)
let mod_add (a : Z.t) (b : Z.t) : Z.t =
  Z.erem (Z.add a b) curve_order
 
(** Use Euclidean remainder to ensure result is always non-negative *)
let mod_mul (a : Z.t) (b : Z.t) : Z.t =
  Z.erem (Z.mul a b) curve_order
 
(** Modular inverse using Fermat's little theorem: a^-1 ≡ a^(n-2) (mod n)
    This works because curve_order is prime.
 *)
let mod_inv (a : Z.t) : Z.t =
  if Z.equal a Z.zero then raise (Failure "Cannot invert zero")
  else Z.powm a (Z.sub curve_order (Z.of_int 2)) curve_order
 
(* ------------------------------------------------------------------ nonce recovery *)
 
(** Recover private key candidate from nonce reuse.
    
    CRITICAL: The recovered key is a CANDIDATE and must be verified
    against the public key via point multiplication before trusting it.
    
    Given two signatures with same r:
      s1 ≡ k1^-1 (z1 + r·d) (mod n)
      s2 ≡ k2^-1 (z2 + r·d) (mod n)
    
    When r1 = r2 = x(R), we have either:
      - Case 1: R1 = R2, so k1 = k2
      - Case 2: R1 = -R2, so k1 ≡ -k2 (mod n)
    
    For Case 1 (k1 = k2):
      s1 - s2 ≡ k^-1 (z1 - z2)  =>  k = (z1 - z2) / (s1 - s2)
      d ≡ r^-1 (k·s1 - z1)  (mod n)
    
    For Case 2 (k1 = -k2):
      s1 + s2 ≡ k^-1 (z1 - z2)  =>  k = (z1 - z2) / (s1 + s2)
      d ≡ r^-1 (k·s1 - z1)  (mod n)
    
    Both formulas for d follow from: s·k ≡ z + r·d, so d ≡ r^-1(k·s - z).
    
    Returns [Some d] if a private key candidate is recoverable via either case.
    Returns [None] if both s1-s2 and s1+s2 are zero (mod n), which is extremely rare.
 *)
let recover_nonce_and_key
    (r : Z.t) (s1 : Z.t) (z1 : Z.t)
    (s2 : Z.t) (z2 : Z.t) : Z.t option =
  try
    let z_diff = mod_sub z1 z2 in
    let r_inv = mod_inv r in
    
    (* Try Case 1: k1 = k2, so k = z_diff / (s1 - s2) *)
    let s_diff = mod_sub s1 s2 in
    if not (Z.equal s_diff Z.zero) then
      try
        let s_diff_inv = mod_inv s_diff in
        let k = mod_mul z_diff s_diff_inv in
        (* d = r^-1 (k·s1 - z1) *)
        let k_s1 = mod_mul k s1 in
        let numerator = mod_sub k_s1 z1 in
        Some (mod_mul r_inv numerator)
      with Failure _ -> None
    else
      (* Try Case 2: k1 = -k2, so k = z_diff / (s1 + s2) *)
      let s_sum = mod_add s1 s2 in
      if not (Z.equal s_sum Z.zero) then
        try
          let s_sum_inv = mod_inv s_sum in
          let k = mod_mul z_diff s_sum_inv in
          (* d = r^-1 (k·s1 - z1) *)
          let k_s1 = mod_mul k s1 in
          let numerator = mod_sub k_s1 z1 in
          Some (mod_mul r_inv numerator)
        with Failure _ -> None
      else
        (* Both s1-s2 and s1+s2 are zero: astronomically rare *)
        None
  with Failure _ -> None
 
(* ------------------------------------------------------------------ HNP analysis *)
 
(** PLACEHOLDER: NOT IMPLEMENTED
    
    A proper HNP analysis would:
    1. Assume a bound B on the nonce magnitude (e.g., B = 2^128)
    2. Construct a lattice from (r_i, s_i, z_i) tuples
    3L. Run LLL or BKZ basis reduction
    4. Extract nonce bits from the reduced basis
    
    Currently, this function returns zeros. HNP_partial attack vectors
    are NEVER emitted by detect_hnp_attack below.
 *)
let compute_hnp (_observations : observation list) : hnp_result =
  {
    leaked_bits = 0;
    bound = curve_order;
    hnp_difficulty = float_of_int bit_length_n;
    confidence = 0.0;
  }
 
(* ------------------------------------------------------------------ nonce relationship detection *)
 
(** Detect relationship between two observations.
    
    CRYPTOGRAPHIC FACT: The only meaningful relationship is exact r equality.
    
    r = x(k·G) mod n is a nonlinear function of k. Two different nonces k1, k2
    produce r values that are essentially uniformly distributed over [0, n).
    
    Bit similarity, Hamming distance, or leading-bit agreement do NOT indicate
    related nonces or any exploitable structure. They are cryptographically
    meaningless coincidences.
    
    Equal r (Same_nonce) is the ONLY condition that allows nonce recovery,
    because it means R1 = ±R2, which constrains k1 = ±k2 (mod n).
 *)
let analyze_pair (obs1 : observation) (obs2 : observation) : nonce_relationship =
  if Z.equal obs1.r obs2.r then
    Same_nonce obs1.r
  else
    Unrelated
 
(* ------------------------------------------------------------------ attack detection *)
 
(** Check if nonce reuse allows private key recovery.
    
    Scans all pairs of observations for same r. For each pair,
    attempts to recover a private key candidate via recover_nonce_and_key.
    
    Time complexity: O(n^2) with array indexing (was O(n^3) with List.nth).
 *)
let detect_nonce_reuse_attack (obs_list : observation list) : attack_vector list =
  let reuse_attacks = ref [] in
  let arr = Array.of_list obs_list in
  let n = Array.length arr in
  
  for i = 0 to n - 1 do
    for j = i + 1 to n - 1 do
      let obs1 = arr.(i) in
      let obs2 = arr.(j) in
      
      if Z.equal obs1.r obs2.r then
        (* Same r: attempt recovery *)
        match obs1.z, obs2.z with
        | Some z1, Some z2 when not (Z.equal z1 z2) ->
          (match recover_nonce_and_key obs1.r obs1.s z1 obs2.s z2 with
           | Some d ->
             reuse_attacks := Nonce_reuse {
               r = obs1.r;
               s1 = obs1.s;
               s2 = obs2.s;
               z1;
               z2;
               private_key = d;
             } :: !reuse_attacks
           | None -> ())
        | _ -> ()
    done
  done;
  
  !reuse_attacks
 
(** DISABLED: HNP detection is not implemented.
    
    This function always returns [] because compute_hnp always returns
    a placeholder hnp_result with leaked_bits = 0, and the condition
    (hnp.leaked_bits > 10) is never true.
    
    Do not emit HNP_partial attack vectors on healthy transactions
    that merely have multiple inputs.
 *)
let detect_hnp_attack (_obs_list : observation list) : attack_vector list =
  []
 
(** DISABLED: Lattice attack detection is not implemented.
    
    This function always returns [] to avoid false positives.
    
    A proper implementation would:
    1. Check for ≥ 5 equations with sufficient linear independence
    2. Form an actual lattice basis
    3L. Run LLL reduction
    4. Estimate nonce bits from the reduced vectors
 *)
let detect_lattice_attack (_obs_list : observation list) : attack_vector list =
  []
 
(** Detect all applicable attacks.
    
    Current strategy: Check for nonce reuse first (highest severity).
    Return immediately if found. Otherwise return empty list.
    
    TODO: Add HNP/lattice detection once real lattice implementation exists.
 *)
let detect_attacks (obs_list : observation list) : attack_vector list =
  if List.length obs_list < 2 then []
  else
    let nonce_reuse = detect_nonce_reuse_attack obs_list in
    if List.length nonce_reuse > 0 then nonce_reuse
    else []
 
(* ------------------------------------------------------------------ risk scoring *)
 
let compute_risk_score (attacks : attack_vector list) : float =
  List.fold_left (fun acc attack ->
    let weight = match attack with
      | Nonce_reuse _ -> 1.0      (* CRITICAL: private key recoverable *)
      | HNP_partial _ -> 0.0  (* Never emitted *)
      | Lattice_candidate _ -> 0.0     (* Never emitted *)
      | No_attack -> 0.0
    in
    max acc weight
  ) 0.0 attacks
 
let risk_level_of_score (score : float) : string =
  if score >= 0.8 then "CRITICAL"
  else if score >= 0.6 then "HIGH"
  else if score >= 0.4 then "MEDIUM"
  else if score >= 0.2 then "LOW"
  else "NONE"
 
let summary_of_attacks (attacks : attack_vector list) : string =
  match attacks with
  | [] -> "No nonce reuse detected"
  | Nonce_reuse { r; _ } :: _ ->
    (* The full r, never a prefix of it. This used to print String.sub 0 16,
       which broke the same no-truncation rule the UI is held to: a reader could
       not compare the value against a transaction. *)
    Printf.sprintf "CRITICAL: Nonce reuse detected (r=%s) - private key may be recoverable"
      (Z.to_string r)
  | HNP_partial _ :: _ -> "Placeholder: HNP not implemented"
  | Lattice_candidate _ :: _ -> "Placeholder: Lattice not implemented"
  | No_attack :: _ -> "No vulnerabilities detected"

 
(* ------------------------------------------------------------------ analysis results *)
 
(** Analyze all observations from a single transaction input.
    
    Computes all-pairs pairwise relationships and detects attacks.
    Time complexity: O(n^2) where n = number of signatures.
 *)
let analyze_input
    (txid : string)
    (input_index : int)
    (obs_list : Analysis_signature.Observation.observation list) : input_analysis =
  
  if List.length obs_list = 0 then
    {
      txid;
      input_index;
      relationships = [];
      attack_vectors = [];
      risk_score = 0.0;
      risk_level = "NONE";
      summary = "No signatures to analyze";
    }
  else if List.length obs_list = 1 then
    {
      txid;
      input_index;
      relationships = [];
      attack_vectors = [];
      risk_score = 0.0;
      risk_level = "NONE";
      summary = "Single signature - no pairwise relationships";
    }
  else
    (* Analyze all pairs *)
    let relationships = ref [] in
    let arr = Array.of_list obs_list in
    let n = Array.length arr in
    for i = 0 to n - 1 do
      for j = i + 1 to n - 1 do
        let rel = analyze_pair arr.(i) arr.(j) in
        relationships := rel :: !relationships
      done
    done;
    
    (* Detect attacks *)
    let attack_vectors = detect_attacks obs_list in
    let risk_score = compute_risk_score attack_vectors in
    let risk_level = risk_level_of_score risk_score in
    let summary = summary_of_attacks attack_vectors in
    
    {
      txid;
      input_index;
      relationships = !relationships;
      attack_vectors;
      risk_score;
      risk_level;
      summary;
    }
 
(** Analyze all inputs in a transaction *)
let analyze_transaction
    (txid : string)
    (inputs : Analysis_signature.Observation.observation list list) : input_analysis list =
  List.mapi (fun idx input_obs ->
    analyze_input txid idx input_obs
  ) inputs
 
(* ------------------------------------------------------------------ formatting *)
 
let format_result (result : input_analysis) : string =
  Printf.sprintf
    "Transaction %s, Input %d:\n  Risk: %.2f (%s)\n  Attacks: %d\n  %s"
    result.txid result.input_index result.risk_score result.risk_level
    (List.length result.attack_vectors) result.summary
 
let format_nonce_relationship (rel : nonce_relationship) : string =
  match rel with
  | Unrelated -> "Unrelated"
  | Same_nonce r -> Printf.sprintf "Same nonce (r=%s)" (Z.to_string r)
  | Related_nonce { r1; r2; similarity; _ } ->
    (* Full r1 and r2. The old format printed 8-character prefixes with a
       trailing ellipsis, which is exactly the elision this project forbids
       everywhere else. *)
    Printf.sprintf "Related nonces (sim=%.2f, r1=%s, r2=%s)"
      similarity (Z.to_string r1) (Z.to_string r2)
  | HNP_candidate { hnp; _ } ->
    Printf.sprintf "HNP candidate (leaked_bits=%d, confidence=%.2f)"
      hnp.leaked_bits hnp.confidence
 
let format_attack_vector (attack : attack_vector) : string =
  match attack with
  | Nonce_reuse { r; private_key; _ } ->
    (* Both values in full. A truncated private key is not usable for the only
       thing this line exists to enable: verifying the recovery. *)
    Printf.sprintf "Nonce reuse (r=%s) → recovered d=%s"
      (Z.to_string r)
      (Z.to_string private_key)
  | HNP_partial { leaked_bits; _ } ->
    Printf.sprintf "HNP attack (leaked_bits=%d)" leaked_bits
  | Lattice_candidate { n_equations; _ } ->
    Printf.sprintf "Lattice attack (%d equations)" n_equations
  | No_attack -> "No attack"
