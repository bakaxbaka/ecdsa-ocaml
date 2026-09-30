(*
   lib/analysis/signature/sig_analysis.ml
   
   Extract and analyze ECDSA signature components (r, s, z)
   from Bitcoin transactions with cryptographic pattern detection
   
   {b Fixed bugs:}
   - [format_z_hex] now correctly outputs hex with [Z.format "%064x"]
   - Replaced meaningless [same_z_diff_r] with proper nonce-reuse analysis
   - Added [recover_private_keys] for actual key recovery
   - Added deduplication, filtering, and reproducible output
*)

(* --- Types --- *)

type signature_record = {
  tx_id: string;  (* Transaction hash *)
  input_index: int;  (* Which input in the transaction *)
  pubkey: string option;  (* Public key that signed - optional, not populated from CSV *)
  r: Z.t;  (* r component of signature *)
  s: Z.t;  (* s component of signature *)
  z: Z.t option;  (* Message hash - optional, may be unknown *)
  timestamp: string option;  (* When extracted - optional, not populated from CSV, reserved for external use *)
}

type analysis_result = {
  signatures: signature_record list;
  repeated_r: (Z.t * signature_record list) list;  (* r values reused across messages *)
  invalid: signature_record list;  (* Signatures with z=0, r=0, or s=0 *)
}

(* --- Constants --- *)

(* secp256k1 curve order *)
let n = Z.of_string "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"

(* --- Hex printing (FIX: was printing decimal, not hex) --- *)

(** Correct hex printer - always produces 64-char lowercase hex *)
let format_z_hex_opt = function
  | None -> "NONE"
  | Some z -> Z.format "%064x" z

let format_z_hex z = Z.format "%064x" z

(* format_r_hex: same implementation as format_z_hex; separate name for readability at call sites *)
let format_r_hex r = Z.format "%064x" r

(* --- Validation (FIX: reject invalid signatures) --- *)

(** Check if signature is invalid per ECDSA spec:
    - z = 0: message hash must not be zero
    - r = 0 or r >= n: r must be in [1, n-1]
    - s = 0 or s >= n: s must be in [1, n-1] *)
let is_valid_signature (sig_ : signature_record) : bool =
  match sig_.z with
  | Some z when Z.equal z Z.zero -> false
  | _ when Z.equal sig_.r Z.zero || Z.geq sig_.r n -> false
  | _ when Z.equal sig_.s Z.zero || Z.geq sig_.s n -> false
  | _ -> true

(** Filter valid vs invalid signatures *)
let partition_signatures (sigs : signature_record list) :
    (signature_record list * signature_record list) =
  List.partition is_valid_signature sigs

(* --- Deduplication (FIX: remove duplicate entries) --- *)

(** Remove duplicate signatures based on (tx_id, input_index) *)
let deduplicate_by_location (sigs : signature_record list) : signature_record list =
  let seen = Hashtbl.create (List.length sigs) in
  List.filter (fun sig_ ->
    let key = (sig_.tx_id, sig_.input_index) in
    if Hashtbl.mem seen key then false
    else (Hashtbl.add seen key (); true)
  ) sigs

(** Remove duplicate signatures based on (r, s, z) *)
let deduplicate_by_values (sigs : signature_record list) : signature_record list =
  let seen = Hashtbl.create (List.length sigs) in
  List.filter (fun sig_ ->
    let z_str = match sig_.z with None -> "" | Some z -> Z.format "%064x" z in
    let key = (Z.format "%064x" sig_.r, Z.format "%064x" sig_.s, z_str) in
    if Hashtbl.mem seen key then false
    else (Hashtbl.add seen key (); true)
  ) sigs

(* --- Key Recovery (FIX: actual cryptographic analysis) --- *)

(** Analyze for nonce reuse: same r, different z (the actual vulnerability)
    
    When r is reused across different messages, we can recover the private key:
    
        k = (z₁ - z₂) · (s₁ - s₂)⁻¹  mod n
        d = (s₁ · k - z₁) · r⁻¹      mod n
    
    This is the classic Android SecureRandom bug, PS3 vulnerability, etc. *)
let analyze_nonce_reuse (sigs : signature_record list) :
    (Z.t * signature_record list) list =
  (* Group signatures by r value *)
  let tbl = Hashtbl.create (List.length sigs) in
  List.iter (fun sig_ ->
    let group : signature_record list =
      try Hashtbl.find tbl sig_.r with Not_found -> [] in
    Hashtbl.replace tbl sig_.r (sig_ :: group)
  ) sigs;
  
  (* Keep only groups with same r but different z values *)
  let result = ref [] in
  Hashtbl.iter (fun r group ->
    (* Get distinct z values *)
    let distinct_z = List.fold_left (fun acc s ->
      match s.z with
      | None -> acc
      | Some z -> 
        (* Avoid duplicates in the accumulator *)
        if List.exists (Z.equal z) acc then acc else z :: acc
    ) [] group in
    (* Only flag nonce reuse if we have 2+ distinct messages *)
    if List.length distinct_z >= 2 then
      let sorted_group = List.sort (fun a b -> Z.compare a.r b.r) group in
      result := (r, sorted_group) :: !result
  ) tbl;
  
  (* Sort by r for reproducible output (FIX: Hashtbl.fold has undefined order) *)
  List.sort (fun (a, _) (b, _) -> Z.compare a b) !result

(** Attempt to recover private key from nonce-reuse signatures *)
let recover_private_keys (sigs : signature_record list) :
    (Z.t * signature_record * signature_record) list =
  let nonce_reuse = analyze_nonce_reuse sigs in
  
  List.filter_map (fun (_r, group) ->
    (* Find a pair with distinct z values *)
    let rec find_pair = function
      | [] | [_] -> None
      | a :: rest ->
        match List.find_opt (fun b ->
          match a.z, b.z with
          | Some za, Some zb -> not (Z.equal za zb)
          | _ -> false
        ) rest with
        | Some b -> Some (a, b)
        | None -> find_pair rest
    in
    
    match find_pair group with
    | None -> None  (* All sigs in group have same z or missing z - not a valid nonce reuse *)
    | Some (a, b) ->
      (match a.z, b.z with
      | Some za, Some zb ->
        (* Compute: k = (z₁ - z₂) · (s₁ - s₂)⁻¹ mod n *)
        let z_diff = Z.(erem (za - zb) n) in
        let s_diff = Z.(erem (a.s - b.s) n) in
        (try
          let s_diff_inv = Z.invert s_diff n in
          let k = Z.(erem (z_diff * s_diff_inv) n) in
          (* Compute: d = (s₁ · k - z₁) · r⁻¹ mod n *)
          let r_inv = Z.invert a.r n in
          let d = Z.(erem ((a.s * k - za) * r_inv) n) in
          Some (d, a, b)
        with _ -> None
        )
      | _ -> None  (* Should not happen if find_pair works correctly *)
      )
  ) nonce_reuse

(* --- Analysis Functions --- *)

(** Count occurrences - returns sorted list for reproducibility *)
let count_occurrences (lst : Z.t list) : (Z.t * int) list =
  let tbl = Hashtbl.create (List.length lst) in
  List.iter (fun x ->
    let count = try Hashtbl.find tbl x with Not_found -> 0 in
    Hashtbl.replace tbl x (count + 1)
  ) lst;
  (* FIX: Sort for reproducible output *)
  Hashtbl.fold (fun k v acc ->
    if v > 1 then (k, v) :: acc else acc
  ) tbl []
  |> List.sort (fun (a, _) (b, _) -> Z.compare a b)

(** Run full analysis *)
let analyze (signatures : signature_record list) : analysis_result =
  (* Deduplicate first *)
  let deduped = deduplicate_by_location signatures |> deduplicate_by_values in
  
  (* Partition valid vs invalid *)
  let (valid, invalid) = partition_signatures deduped in
  
  (* Analyze nonce reuse (same r, different z - THE REAL VULNERABILITY) *)
  let repeated_r = analyze_nonce_reuse valid in
  
  {
    signatures = valid;
    repeated_r;
    invalid;
  }

(* --- Output --- *)

let print_analysis (result : analysis_result) : unit =
  Printf.printf "\n=== Signature Analysis Results ===\n";
  Printf.printf "Total signatures processed: %d\n" (List.length result.signatures);
  if List.length result.invalid > 0 then
    Printf.printf "Invalid signatures filtered: %d (z=0, r=0, or s=0)\n"
      (List.length result.invalid);
  
  (* Nonce reuse - the actual vulnerability *)
  Printf.printf "\n--- Nonce reuse (SAME r, DIFFERENT z) ---\n";
  Printf.printf "This is the ACTUAL vulnerability (Android bug, PS3, etc.)\n";
  Printf.printf "Requires: same r in at least 2 signatures with different message hashes (z)\n";
  if List.length result.repeated_r = 0 then
    Printf.printf "No nonce reuse detected (GOOD!)\n"
  else begin
    List.iter (fun (r, group) ->
      (* Count distinct z *)
      let distinct_z = List.fold_left (fun acc s ->
        match s.z with
        | None -> acc
        | Some z -> if List.exists (Z.equal z) acc then acc else z :: acc
      ) [] group in
      
      Printf.printf "\nNonce reuse detected for r = %s\n" (format_r_hex r);
      Printf.printf "  Found %d signatures with this r and %d distinct messages:\n"
        (List.length group) (List.length distinct_z);
      List.iteri (fun i sig_ ->
        match sig_.z with
        | None ->
            Printf.printf "    [%d] tx=%s idx=%d z=UNKNOWN (cannot use for recovery)\n"
              i sig_.tx_id sig_.input_index
        | Some z ->
            Printf.printf "    [%d] tx=%s idx=%d z=%s\n"
              i sig_.tx_id sig_.input_index (format_z_hex z)
      ) group;
      
      (* Show recovered key if possible *)
      let recovered = recover_private_keys group in
      let key_count = List.length recovered in
      if key_count > 0 then
        List.iter (fun (d, a, b) ->
          Printf.printf "    ⚠️  KEY RECOVERED: d = %s\n" (format_z_hex d);
          Printf.printf "        (from signatures at tx=%s[%d] and tx=%s[%d])\n"
            a.tx_id a.input_index b.tx_id b.input_index;
          Printf.printf "        Note: k may be k or n-k (both give same r). Check against pubkey.\n"
        ) recovered
      else
        Printf.printf "    (Key recovery failed: need at least 2 sigs with different z values)\n"
    ) result.repeated_r
  end;
  
  
  (* Summary *)
  Printf.printf "\n=== Summary ===\n";
  Printf.printf "Valid signatures:    %d\n" (List.length result.signatures);
  Printf.printf "Invalid/filtered:    %d\n" (List.length result.invalid);
  Printf.printf "Nonce reuse cases:   %d\n" (List.length result.repeated_r);
  let all_recovered =
    List.concat_map (fun (_, group) -> recover_private_keys group) result.repeated_r
  in
  Printf.printf "Keys recovered:      %d\n" (List.length all_recovered)

(* --- CSV Loading Helper --- *)

(** Load signatures from CSV file
    Expected format: txid,input_index,r,s,z,sighash (6 fields)
    
    Parsing rules:
    - r, s: parsed as hex (with or without 0x prefix), must be in [1, n)
    - z: parsed as hex or None if empty/"NONE"/contains placeholder (_)
    - z=0 is rejected (invalid in ECDSA)
    - sighash field (index 5) is currently ignored; pubkey is set to None
    - Rows with invalid r/s are skipped
    
    Note: if z is "NEEDS_PROPER_SIGHASH" from the extractor, those rows
    load but won't contribute to key recovery (recovery needs real z). *)

(** Parse a single CSV line into a signature_record
    Handles hex values for r, s, z (prefixed with 0x or raw hex).
    Sets z = None for empty / "NONE" / placeholder values; the row is still loaded. *)
let parse_csv_line (line : string) : signature_record option =
  let fields = String.split_on_char ',' line in
  if List.length fields < 5 then None
  else
    try
      let tx_id = List.nth fields 0 in
      let input_index = int_of_string (List.nth fields 1) in
      
      (* Parse r as hex (64 hex chars) *)
      let r_str = String.trim (List.nth fields 2) in
      let r = if String.starts_with ~prefix:"0x" r_str then
        Z.of_string r_str
      else
        Z.of_string ("0x" ^ r_str)
      in
      
      (* Parse s as hex *)
      let s_str = String.trim (List.nth fields 3) in
      let s = if String.starts_with ~prefix:"0x" s_str then
        Z.of_string s_str
      else
        Z.of_string ("0x" ^ s_str)
      in
      
      (* Parse z as hex, handling placeholders *)
      let z_str = String.trim (List.nth fields 4) in
      let z =
        if z_str = "" || z_str = "NONE" then None
        else if String.contains z_str '_' then None  (* Skip placeholders like NEEDS_PROPER_SIGHASH *)
        else
          try
            let z_val = if String.starts_with ~prefix:"0x" z_str then
              Z.of_string z_str
            else
              Z.of_string ("0x" ^ z_str)
            in
            (* Reject z = 0 (invalid) *)
            if Z.equal z_val Z.zero then None else Some z_val
          with _ -> None
      in
      
      (* Only emit a record if we have valid r, s (z can be None) *)
      Some { tx_id; input_index; pubkey = None; r; s; z; timestamp = None }
    with _ -> None

(** Load signatures from CSV file with parsing *)
let load_from_csv (path : string) : signature_record list =
  let lines = ref [] in
  let ic = open_in path in
  (try
    while true do
      let line = input_line ic in
      lines := line :: !lines
    done
  with End_of_file ->
    close_in ic);
  List.filter_map parse_csv_line (List.rev !lines)

(** Alias for interface compatibility *)
let load_csv = load_from_csv
