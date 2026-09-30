(* lib/api/encode.ml
   JSON encoders for every analysis type the project exposes.

   Every encoder is total: no value is dropped, defaulted away, or shortened.
   Where the domain type carries an [option], the JSON carries either a real
   value or [null] — never a fabricated placeholder. *)

open Json

(** [analysis_signature] is a wrapped library, so its [Observation] module is
    only reachable as [Analysis_signature.Observation].  The rest of this file
    refers to it by the short name, as the library's own modules do. *)
module Observation = Analysis_signature.Observation

(* ------------------------------------------------------------------ crypto *)

let field (f : Field.t) : t = Obj [ "hex", Str (Field.to_hex f); "dec", Str (Field.to_z f |> Z.to_string) ]

let point (p : Curve.Point.t) : t =
  (* A point is encoded by its SEC1 compressed form, which is the canonical
     serialisation, plus the affine coordinates when the underlying
     representation exposes them.  A point at infinity has no affine
     coordinates, so those are [null] rather than invented. *)
  Obj
    [ "compressed_hex", Str (Curve.Point.to_compressed p);
      "uncompressed_hex", Str (Curve.Point.to_uncompressed p);
      "x", opt field (Curve.Point.x p);
      "y", opt field (Curve.Point.y p) ]

let point_opt = function None -> Null | Some p -> point p

let s_form = function
  | Observation.Low_s -> Str "low_s"
  | Observation.High_s -> Str "high_s"

let sighash_protocol = function
  | Observation.Legacy_sighash -> Str "legacy"
  | Observation.Bip143_sighash -> Str "bip143"
  | Observation.Unknown_protocol -> Str "unknown"

let script_type (t : Classify.script_type) : t = Str (Classify.to_string t)

(* Human name for a sighash byte, from the values the DER parser accepts. *)
let sighash_type_name (b : int) : string =
  match b with
  | 0x01 -> "SIGHASH_ALL"
  | 0x02 -> "SIGHASH_NONE"
  | 0x03 -> "SIGHASH_SINGLE"
  | 0x81 -> "SIGHASH_ALL|ANYONECANPAY"
  | 0x82 -> "SIGHASH_NONE|ANYONECANPAY"
  | 0x83 -> "SIGHASH_SINGLE|ANYONECANPAY"
  | _ -> "UNKNOWN"

let sighash_field (b : int) : t =
  Obj [ "byte", Str (hex_byte b); "name", Str (sighash_type_name b) ]

(* ------------------------------------------------------------------ der *)

let der_parsed (d : Der.parsed) : t =
  Obj [ "r", z d.r; "s", z d.s; "sighash", sighash_field d.sighash ]

(* ------------------------------------------------------------------ transaction *)

let outpoint (o : Types.outpoint) : t =
  Obj
    [ "txid_hex_internal", Str (Hex.of_bytes o.txid);
      "txid_display", Str (Types.txid_to_display_hex o.txid);
      "vout", Int o.vout ]

let tx_input (i : Types.tx_input) : t =
  Obj
    [ "previous_output", outpoint i.previous_output;
      "script_sig", bytes i.script_sig;
      "sequence", Int i.sequence;
      "is_coinbase", Bool (Types.is_coinbase i) ]

let tx_output (o : Types.tx_output) : t =
  Obj
    [ "value", Str (Int64.to_string o.value);
      "script_pubkey", bytes o.script_pubkey ]

let transaction (tx : Types.transaction) : t =
  Obj
    [ "version", Int tx.version;
      "inputs", List (List.map tx_input tx.inputs);
      "input_count", Int (List.length tx.inputs);
      "outputs", List (List.map tx_output tx.outputs);
      "output_count", Int (List.length tx.outputs);
      "witnesses",
        List (List.map (fun ws -> List (List.map bytes ws)) tx.witnesses);
      "lock_time", Int tx.lock_time;
      "segwit", Bool tx.segwit ]

(* ------------------------------------------------------------------ script *)

let script_opcode (op : int) : string =
  (* A few names that carry meaning in analysis output; the rest stay numeric
     rather than being guessed at. *)
  match op with
  | 0x00 -> "OP_0"
  | 0x4c -> "OP_PUSHDATA1"
  | 0x4d -> "OP_PUSHDATA2"
  | 0x4e -> "OP_PUSHDATA4"
  | 0x4f -> "OP_1NEGATE"
  | 0x51 -> "OP_1"
  | 0x6a -> "OP_RETURN"
  | 0x76 -> "OP_DUP"
  | 0x88 -> "OP_EQUALVERIFY"
  | 0xa9 -> "OP_HASH160"
  | 0xac -> "OP_CHECKSIG"
  | _ -> Printf.sprintf "OP_%02x" op

let script_instruction (i : Script.instruction) : t =
  let op = Script.opcode_of i in
  let base =
    [ "opcode", Str (hex_byte op);
      "opcode_name", Str (script_opcode op);
      "is_push", Bool (Script.is_push i) ]
  in
  match i with
  | Script.Push_data _ ->
    Obj (("kind", Str "push") :: ("data", bytes (Script.data_of i)) :: base)
  | Script.Opcode _ -> Obj (("kind", Str "opcode") :: base)

let script (s : Script.t) : t = List (List.map script_instruction s)

(* ------------------------------------------------------------------ signature extraction *)

let parsed_sig (p : Signature_extraction.parsed_sig) : t =
  Obj
    [ "r", z p.r;
      "s", z p.s;
      "sighash", sighash_field p.sighash ]

let extraction_result (r : Signature_extraction.signature_extraction_result) : t =
  Obj
    [ "input_index", Int r.input_index;
      "signatures", List (List.map parsed_sig r.signatures);
      "signature_count", Int (List.length r.signatures);
      "public_key", bytes_opt r.public_key;
      "script_sig", bytes r.script_sig;
      "witness_index", opt (fun i -> Int i) r.witness_index;
      "script_push_index",
        List (List.map (fun i -> Int i) r.script_push_index) ]

(* ------------------------------------------------------------------ observation *)

let observation (o : Observation.observation) : t =
  Obj
    [ "txid", Str o.txid;
      "input_index", Int o.input_index;
      "script_type", script_type o.script_type;
      "sighash_protocol", sighash_protocol o.sighash_protocol;
      "public_key", point_opt o.public_key;
      "public_key_hex", Str o.public_key_hex;
      "r", z o.r;
      "s", z o.s;
      "s_form", s_form o.s_form;
      "sighash", sighash_field o.sighash_type;
      "z", opt z o.z;
      "ecdsa_valid", opt (fun b -> Bool b) o.ecdsa_valid;
      "raw_der_hex", Str o.raw_der_hex ]

(* ------------------------------------------------------------------ nonce relationship *)

let hnp_result (h : Nonce.hnp_result) : t =
  Obj
    [ "leaked_bits", Int h.leaked_bits;
      "bound", z h.bound;
      "hnp_difficulty", Float h.hnp_difficulty;
      "confidence", Float h.confidence ]

let nonce_relationship (r : Nonce.nonce_relationship) : t =
  match r with
  | Nonce.Unrelated -> Obj [ "kind", Str "unrelated" ]
  | Nonce.Same_nonce v ->
    Obj [ "kind", Str "same_nonce"; "r", z v ]
  | Nonce.Related_nonce { r1; r2; z1; z2; similarity } ->
    Obj
      [ "kind", Str "related_nonce";
        "r1", z r1; "r2", z r2;
        "z1", z z1; "z2", z z2;
        "similarity", Float similarity ]
  | Nonce.HNP_candidate { r_values; z_values; hnp } ->
    Obj
      [ "kind", Str "hnp_candidate";
        "r_values", List (List.map z r_values);
        "z_values", List (List.map z z_values);
        "hnp", hnp_result hnp ]

let attack_vector (a : Nonce.attack_vector) : t =
  match a with
  | Nonce.Nonce_reuse { r; s1; s2; z1; z2; private_key } ->
    Obj
      [ "kind", Str "nonce_reuse";
        "r", z r; "s1", z s1; "s2", z s2; "z1", z z1; "z2", z z2;
        "private_key_candidate", z private_key ]
  | Nonce.HNP_partial { leaked_bits; observations; hnp } ->
    Obj
      [ "kind", Str "hnp_partial";
        "leaked_bits", Int leaked_bits;
        "observation_count", Int (List.length observations);
        "observations", List (List.map observation observations);
        "hnp", hnp_result hnp ]
  | Nonce.Lattice_candidate { n_equations; lattice_rank; observations } ->
    Obj
      [ "kind", Str "lattice_candidate";
        "n_equations", Int n_equations;
        "lattice_rank", Int lattice_rank;
        "observation_count", Int (List.length observations);
        "observations", List (List.map observation observations) ]
  | Nonce.No_attack -> Obj [ "kind", Str "no_attack" ]

let input_analysis (a : Nonce.input_analysis) : t =
  Obj
    [ "txid", Str a.txid;
      "input_index", Int a.input_index;
      "relationships", List (List.map nonce_relationship a.relationships);
      "attack_vectors", List (List.map attack_vector a.attack_vectors);
      "risk_score", Float a.risk_score;
      "risk_level", Str a.risk_level;
      "summary", Str a.summary ]

(* ------------------------------------------------------------------ statistics *)

let sig_form_stats (s : Statistics.sig_form_stats) : t =
  Obj
    [ "low_s_count", Int s.low_s_count;
      "high_s_count", Int s.high_s_count;
      "low_s_ratio", Float s.low_s_ratio ]

let sighash_stats (s : Statistics.sighash_stats) : t =
  Obj
    [ "all_count", Int s.all_count;
      "none_count", Int s.none_count;
      "single_count", Int s.single_count;
      "anyonecanpay_count", Int s.anyonecanpay_count;
      "distribution",
        List
          (List.map
             (fun (b, n) ->
                Obj [ "sighash", sighash_field b; "count", Int n ])
             s.distribution) ]

let z_stats (s : Statistics.z_stats) : t =
  Obj
    [ "mean", Float s.mean;
      "variance", Float s.variance;
      "std_dev", Float s.std_dev;
      "min_value", z s.min_value;
      "max_value", z s.max_value;
      "range", z s.range;
      (* [distribution_buckets] is an [int array] — every bucket is emitted, in
         order, with its index, so a client cannot confuse a short read with a
         short array. *)
      "distribution_buckets",
        List
          (List.mapi (fun i n -> Obj [ "bucket", Int i; "count", Int n ])
             (Array.to_list s.distribution_buckets));
      "bucket_count", Int (Array.length s.distribution_buckets) ]

let pubkey_stats (s : Statistics.pubkey_stats) : t =
  Obj
    [ "compressed_count", Int s.compressed_count;
      "uncompressed_count", Int s.uncompressed_count;
      "recovery_failures", Int s.recovery_failures;
      "recovery_rate", Float s.recovery_rate ]

let script_type_stats (s : Statistics.script_type_stats) : t =
  Obj
    [ "p2pkh_count", Int s.p2pkh_count;
      "p2pk_count", Int s.p2pk_count;
      "p2wpkh_count", Int s.p2wpkh_count;
      "p2sh_count", Int s.p2sh_count;
      "p2wsh_count", Int s.p2wsh_count;
      "p2tr_count", Int s.p2tr_count;
      "op_return_count", Int s.op_return_count;
      "unknown_count", Int s.unknown_count ]

let ecdsa_stats (s : Statistics.ecdsa_stats) : t =
  Obj
    [ "verified_count", Int s.verified_count;
      "failed_count", Int s.failed_count;
      "verification_rate", Float s.verification_rate ]

let aggregate_stats (s : Statistics.aggregate_stats) : t =
  Obj
    [ "total_inputs", Int s.total_inputs;
      "total_signatures", Int s.total_signatures;
      "sig_forms", sig_form_stats s.sig_forms;
      "sighash_types", sighash_stats s.sighash_types;
      "z_values", opt z_stats s.z_values;
      "pubkeys", pubkey_stats s.pubkeys;
      "script_types", script_type_stats s.script_types;
      "ecdsa_verification", ecdsa_stats s.ecdsa_verification ]

(* ------------------------------------------------------------------ pipeline *)

let transaction_analysis (a : Analysis.transaction_analysis) : t =
  Obj
    [ "txid", Str a.txid;
      "input_analyses", List (List.map input_analysis a.input_analyses);
      "aggregate_stats", aggregate_stats a.aggregate_stats;
      "critical_findings",
        List (List.map (fun s -> Str s) a.critical_findings) ]

let batch_analysis (a : Analysis.batch_analysis) : t =
  Obj
    [ "transactions", List (List.map transaction_analysis a.transactions);
      "total_critical", Int a.total_critical;
      "total_high", Int a.total_high;
      "total_medium", Int a.total_medium;
      "summary", Str a.summary ]

(** A batch of per-input analyses produced outside [Analysis]. *)
let analysis_batch (xs : Nonce.input_analysis list) : t =
  Obj
    [ "analyses", List (List.map input_analysis xs);
      "count", Int (List.length xs) ]

(** A [Sig_analysis.signature_record]. *)
let signature_record (s : Analysis_signature.Sig_analysis.signature_record) : t =
  Obj
    [ "tx_id", Str s.tx_id;
      "input_index", Int s.input_index;
      "pubkey", (match s.pubkey with None -> Null | Some p -> Str p);
      "r", z s.r;
      "s", z s.s;
      "z", opt z s.z;
      "timestamp", (match s.timestamp with None -> Null | Some t -> Str t) ]
