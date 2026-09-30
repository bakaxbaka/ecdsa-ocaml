(* lib/api/endpoints.ml
   The pure request dispatcher.

   No sockets, no global state, no I/O beyond reading files the caller names.
   [handle] takes a request value and returns a response value, which makes the
   whole API surface testable without starting a server.

   {1 No truncation}

   Nothing here caps, samples, or shortens a result.  There is no [limit]
   parameter and no [max_results].  If a caller ever needs a bound, it must be
   explicit in the request and the response must say so via a ["truncated"]
   field — see {!Response.mk_bounded}, which is the only place allowed to set it.

   Every response carries:
   - the full result, or a typed error;
   - [duration_ms];
   - the complete request that produced it, echoed back verbatim. *)

open Json

(* ------------------------------------------------------------------ errors *)

let error kind message = Obj [ "kind", Str kind; "message", Str message ]

let err_hex detail = error "invalid_hex" detail
let err_input detail = error "invalid_input" detail

(* ------------------------------------------------------------------ request helpers *)

let require_hex (body : t) (key : string) : (string, t) result =
  match member key body with
  | Some (Str s) when String.trim s <> "" -> Ok (String.trim s)
  | Some (Str _) -> Error (error "missing_field" (Printf.sprintf "field %S is empty" key))
  | Some _ -> Error (error "bad_field_type" (Printf.sprintf "field %S must be a string" key))
  | None -> Error (error "missing_field" (Printf.sprintf "field %S is required" key))

let optional_hex (body : t) (key : string) : bytes option =
  match member key body with
  | Some (Str s) when String.trim s <> "" ->
    (match Hex.to_bytes (String.trim s) with Ok b -> Some b | Error _ -> None)
  | _ -> None

let optional_int (body : t) (key : string) (default : int) : int =
  match member key body with
  | Some (Int i) -> i
  | Some (Float f) -> int_of_float f
  | Some (Str s) -> (match int_of_string_opt (String.trim s) with Some i -> i | None -> default)
  | _ -> default

let optional_int64 (body : t) (key : string) : Int64.t option =
  match member key body with
  | Some (Int i) -> Some (Int64.of_int i)
  | Some (Float f) -> Some (Int64.of_float f)
  | Some (Str s) -> Int64.of_string_opt (String.trim s)
  | _ -> None

(* Body-wide empty check: several endpoints legitimately take no body. *)
let body_is_empty = function
  | Null -> true
  | Obj [] -> true
  | _ -> false

(* ------------------------------------------------------------------ decoding a transaction *)

let decode_hex_field (raw : string) : (bytes, t) result =
  match Hex.to_bytes raw with
  | Ok b -> Ok b
  | Error e -> Error (err_hex (Common.Parse_error.to_string e))

let parse_tx_hex (raw : string) : (Types.transaction, t) result =
  match decode_hex_field raw with
  | Error e -> Error e
  | Ok bytes ->
    (match Tx_parser.of_bytes bytes with
     | Ok tx -> Ok tx
     | Error e -> Error (of_parse_error e))

(* ------------------------------------------------------------------ txid vs wtxid *)

(** Resolve the transaction identity fields.

    This is deliberately fussy, because the obvious implementation is wrong.

    BIP141 defines the {b txid} as the double-SHA256 of the transaction
    serialised {b without} its witness data, and the {b wtxid} as the
    double-SHA256 of the full serialisation {b including} witness data.  The two
    differ for every SegWit transaction.

    The parser exposes no serialiser, so we cannot re-serialise a transaction
    with its witness section removed and therefore cannot derive a true txid for
    a SegWit transaction from its bytes.  Hashing the bytes we were handed gives
    the txid for a legacy transaction and the wtxid for a SegWit one.

    Rather than silently labelling the second case "txid" — which is both wrong
    and unverifiable by the caller — this function only ever assigns the derived
    hash to [txid] when it genuinely is the txid.  Otherwise it reports the hash
    separately, says what it actually is, and tells the caller what to supply. *)
let resolve_ids (body : t) (tx : Types.transaction) (raw : bytes option) : string * t =
  let supplied =
    match member "txid" body with
    | Some (Str s) when String.trim s <> "" -> Some (String.trim s)
    | _ -> None
  in
  match supplied with
  | Some s ->
    (s, Obj [ "source", Str "caller_supplied" ])
  | None ->
    (match raw with
     | None ->
       ("",
        Obj
          [ "source", Str "unavailable";
            "note", Str "No raw bytes and no \"txid\" field were supplied, so no identifier could be derived." ])
     | Some b ->
       let derived = Types.txid_to_display_hex (Hash.hash256 b) in
       if tx.segwit then
         ("",
          Obj
            [ "source", Str "derived";
              "value", Str derived;
              "value_is", Str "wtxid";
              "txid_available", Bool false;
              "note", Str "BIP141: a SegWit txid is the double-SHA256 of the transaction serialised WITHOUT witness data, while this hash covers the full serialisation and is therefore the wtxid. The parser exposes no serialiser, so the txid cannot be derived from these bytes. Supply a \"txid\" field for a true txid." ])
       else
         (derived,
          Obj
            [ "source", Str "derived";
              "value", Str derived;
              "value_is", Str "txid";
              "txid_available", Bool true;
              "note", Str "Legacy transaction: the full serialisation equals the witness-free serialisation, so this hash is the txid." ]))

(* ------------------------------------------------------------------ endpoints *)

let ep_health ~root (_body : t) : t =
  Obj
    [ "ok", Bool true;
      "project_root", Str root;
      "ocaml_version", Str Sys.ocaml_version;
      "z_available", Bool true;
      "note",
        Str "GET /api/health returns liveness only; it does not touch the filesystem beyond the root path." ]

let ep_functions ~root (_body : t) : t =
  let ms = Registry.scan ~root in
  match Registry.to_json ms with
  | Obj fields ->
    Obj (("ok", Bool true) :: fields)
  | other -> other

let ep_parse (body : t) : t =
  match require_hex body "hex" with
  | Error e -> e
  | Ok raw ->
    (match parse_tx_hex raw with
     | Error e -> e
     | Ok tx ->
       let raw_bytes = optional_hex body "hex" in
       let (txid, id_info) = resolve_ids body tx raw_bytes in
       Obj
         [ "ok", Bool true;
           "txid", Str txid;
           "id_derivation", id_info;
           "input_count", Int (List.length tx.inputs);
           "output_count", Int (List.length tx.outputs);
           "transaction", Encode.transaction tx ])

let ep_script_classify (body : t) : t =
  match require_hex body "script_pubkey_hex" with
  | Error e -> e
  | Ok raw ->
    (match decode_hex_field raw with
     | Error e -> e
     | Ok bytes_str ->
       let t = Classify.of_script_pubkey bytes_str in
       let instructions = Parser.of_bytes bytes_str in
       Obj
         [ "ok", Bool true;
           "script_pubkey_hex", Str (Hex.of_bytes bytes_str);
           "script_type", Str (Classify.to_string t);
           "is_p2pkh", Bool (t = Classify.P2PKH);
           "is_p2wpkh", Bool (t = Classify.P2WPKH);
           "script_code_for_p2wpkh",
             bytes_opt (Classify.script_code_for_p2wpkh bytes_str);
           "hash160_of_p2pkh", bytes_opt (Classify.hash160_of_p2pkh bytes_str);
           "hash160_of_p2wpkh", bytes_opt (Classify.hash160_of_p2wpkh bytes_str);
           "pubkey_of_p2pk", bytes_opt (Classify.pubkey_of_p2pk bytes_str);
           "instructions",
             (match instructions with
              | Ok s -> Encode.script s
              | Error e -> of_parse_error e) ])

let ep_script_parse (body : t) : t =
  match require_hex body "script_hex" with
  | Error e -> e
  | Ok raw ->
    (match decode_hex_field raw with
     | Error e -> e
     | Ok bytes_str ->
       (match Parser.of_bytes bytes_str with
        | Error e -> of_parse_error e
        | Ok instrs ->
          Obj
            [ "ok", Bool true;
              "script_hex", Str (Hex.of_bytes bytes_str);
              "instruction_count", Int (List.length instrs);
              "instructions", Encode.script instrs ]))

let ep_der_parse (body : t) : t =
  match require_hex body "der_hex" with
  | Error e -> e
  | Ok raw ->
    (match Der.of_hex raw with
     | Error e -> of_der_error e
     | Ok d -> Obj [ "ok", Bool true; "parsed", Encode.der_parsed d ])

let ep_sighash_legacy (body : t) : t =
  match require_hex body "hex" with
  | Error e -> e
  | Ok raw ->
    (match parse_tx_hex raw with
     | Error e -> e
     | Ok tx ->
       let idx = optional_int body "input_index" 0 in
       let sighash = optional_int body "sighash_type" Legacy.sighash_all in
       (match optional_hex body "script_code_hex" with
        | None ->
          Obj
            [ "ok", Bool false;
              "kind", Str "missing_field";
              "message",
                Str "field \"script_code_hex\" is required: the legacy sighash is computed against the scriptPubKey of the output being spent." ]
        | Some sc ->
          (match Legacy.compute tx idx sc sighash with
           | Ok h ->
             Obj
               [ "ok", Bool true;
                 "input_index", Int idx;
                 "sighash", Encode.sighash_field sighash;
                 "script_code", bytes sc;
                 "z", Json.z (Json.z_of_string_be (Bytes.to_string h));
                 "z_bytes", bytes h ]
           | Error `Index_out_of_bounds ->
             error "index_out_of_bounds"
               (Printf.sprintf "input_index %d is out of range for a transaction with %d inputs"
                  idx (List.length tx.inputs))
           | Error `Invalid_sighash_type ->
             error "invalid_sighash_type"
               (Printf.sprintf "sighash type %d has an invalid base type (must be 1, 2 or 3)"
                  sighash))))

let ep_sighash_bip143 (body : t) : t =
  match require_hex body "hex" with
  | Error e -> e
  | Ok raw ->
    (match parse_tx_hex raw with
     | Error e -> e
     | Ok tx ->
       let idx = optional_int body "input_index" 0 in
       let sighash = optional_int body "sighash_type" Bip143.sighash_all in
       (match optional_hex body "script_code_hex", optional_int64 body "value" with
        | None, _ ->
          Obj
            [ "ok", Bool false; "kind", Str "missing_field";
              "message", Str "field \"script_code_hex\" is required for BIP143." ]
        | _, None ->
          Obj
            [ "ok", Bool false; "kind", Str "missing_field";
              "message",
                Str "field \"value\" (satoshis of the spent output) is required for BIP143: the amount is committed to by the signature." ]
        | Some sc, Some v ->
          (match Bip143.compute tx idx sc v sighash with
           | Ok h ->
             Obj
               [ "ok", Bool true;
                 "input_index", Int idx;
                 "sighash", Encode.sighash_field sighash;
                 "script_code", bytes sc;
                 "value", Str (Int64.to_string v);
                 "z", Json.z (Json.z_of_string_be (Bytes.to_string h));
                 "z_bytes", bytes h ]
           | Error `Index_out_of_bounds ->
             error "index_out_of_bounds"
               (Printf.sprintf "input_index %d is out of range for a transaction with %d inputs"
                  idx (List.length tx.inputs))
           | Error `Invalid_sighash_type ->
             error "invalid_sighash_type"
               (Printf.sprintf "sighash type %d has an invalid base type (must be 1, 2 or 3)"
                  sighash))))

let ep_signatures_extract (body : t) : t =
  match require_hex body "hex" with
  | Error e -> e
  | Ok raw ->
    (match parse_tx_hex raw with
     | Error e -> e
     | Ok tx ->
       let all = Signature_extraction.extract tx in
       let per_input =
         List.mapi
           (fun i _ ->
              (i, Signature_extraction.extract_single tx i))
           tx.inputs
       in
       Obj
         [ "ok", Bool true;
           "segwit", Bool tx.segwit;
           "input_count", Int (List.length tx.inputs);
           "extract_all",
             (match all with
              | Ok results -> List (List.map Encode.extraction_result results)
              | Error e -> of_extraction_error e);
           "per_input",
             List
               (List.map
                  (fun (i, r) ->
                     Obj
                       [ "input_index", Int i;
                         "result",
                           (match r with
                            | Ok res -> Encode.extraction_result res
                            | Error e -> of_extraction_error e) ])
                  per_input) ])

let ep_observation_build (body : t) : t =
  match require_hex body "hex" with
  | Error e -> e
  | Ok raw ->
    (match parse_tx_hex raw with
     | Error e -> e
     | Ok tx ->
       let (txid, id_info) = resolve_ids body tx (optional_hex body "hex") in
       let spk_hints =
         match member "spk_hints" body with
         | Some (List xs) -> List.map (function Str s -> Hex.to_bytes s |> Result.to_option | _ -> None) xs
         | _ -> []
       in
       let utxo_values =
         match member "utxo_values" body with
         | Some (List xs) ->
           List.map (function Str s -> Int64.of_string_opt (String.trim s) | Int i -> Some (Int64.of_int i) | _ -> None) xs
         | _ -> []
       in
       let results = Analysis_signature.Observation.build_all tx txid spk_hints utxo_values in
       Obj
         [ "ok", Bool true;
           "txid", Str txid;
           "id_derivation", id_info;
           "input_count", Int (List.length tx.inputs);
           "observation_count", Int (List.length results);
           "observations",
             List
               (List.map
                  (fun (i, r) ->
                     Obj
                       [ "input_index", Int i;
                         "result",
                           (match r with
                            | Ok o -> Encode.observation o
                            | Error e -> of_observation_error e) ])
                  results) ])

let ep_nonce_analyze (body : t) : t =
  match require_hex body "hex" with
  | Error e -> e
  | Ok raw ->
    (match parse_tx_hex raw with
     | Error e -> e
     | Ok tx ->
       let (txid, id_info) = resolve_ids body tx (optional_hex body "hex") in
       let spk_hints =
         match member "spk_hints" body with
         | Some (List xs) -> List.map (function Str s -> Hex.to_bytes s |> Result.to_option | _ -> None) xs
         | _ -> []
       in
       let utxo_values =
         match member "utxo_values" body with
         | Some (List xs) ->
           List.map (function Str s -> Int64.of_string_opt (String.trim s) | Int i -> Some (Int64.of_int i) | _ -> None) xs
         | _ -> []
       in
       let built = Analysis_signature.Observation.build_all tx txid spk_hints utxo_values in
       let ok_obs =
         List.filter_map (function (_, Ok o) -> Some o | _ -> None) built
       in
       let analyses =
         Analysis_signature.Observation.build_all tx txid spk_hints utxo_values
         |> List.mapi (fun i (_, r) ->
             match r with
             | Ok o -> Nonce.analyze_input txid i [o]
             | Error _ -> Nonce.analyze_input txid i [])
       in
       let cross = Nonce.analyze_transaction txid [ ok_obs ] in
       Obj
         [ "ok", Bool true;
           "txid", Str txid;
           "id_derivation", id_info;
           "observation_count", Int (List.length ok_obs);
           "successful_observations", Int (List.length ok_obs);
           "failed_observations",
             Int (List.length built - List.length ok_obs);
           "per_input", List (List.map Encode.input_analysis analyses);
           "cross_transaction", Encode.analysis_batch cross ])

let ep_statistics (body : t) : t =
  match require_hex body "hex" with
  | Error e -> e
  | Ok raw ->
    (match parse_tx_hex raw with
     | Error e -> e
     | Ok tx ->
       let (txid, id_info) = resolve_ids body tx (optional_hex body "hex") in
       let spk_hints =
         match member "spk_hints" body with
         | Some (List xs) -> List.map (function Str s -> Hex.to_bytes s |> Result.to_option | _ -> None) xs
         | _ -> []
       in
       let utxo_values =
         match member "utxo_values" body with
         | Some (List xs) ->
           List.map (function Str s -> Int64.of_string_opt (String.trim s) | Int i -> Some (Int64.of_int i) | _ -> None) xs
         | _ -> []
       in
       let built = Analysis_signature.Observation.build_all tx txid spk_hints utxo_values in
       let ok_obs = List.filter_map (function (_, Ok o) -> Some o | _ -> None) built in
       let stats = Statistics.compute_aggregate_stats [ ok_obs ] in
       Obj
         [ "ok", Bool true;
           "txid", Str txid;
           "id_derivation", id_info;
           "observation_count", Int (List.length ok_obs);
           "failed_observations", Int (List.length built - List.length ok_obs);
           "stats", Encode.aggregate_stats stats;
           "formatted", Str (Statistics.format_stats stats);
           "library_json", Str (Statistics.stats_to_json stats) ])

let ep_sig_analysis (body : t) : t =
  (* This endpoint needs the full signature record type, which includes a z
     value.  We build records from observations so that the analysis runs on
     real extracted data rather than a CSV. *)
  match require_hex body "hex" with
  | Error e -> e
  | Ok raw ->
    (match parse_tx_hex raw with
     | Error e -> e
     | Ok tx ->
       let (txid, id_info) = resolve_ids body tx (optional_hex body "hex") in
       let spk_hints =
         match member "spk_hints" body with
         | Some (List xs) -> List.map (function Str s -> Hex.to_bytes s |> Result.to_option | _ -> None) xs
         | _ -> []
       in
       let utxo_values =
         match member "utxo_values" body with
         | Some (List xs) ->
           List.map (function Str s -> Int64.of_string_opt (String.trim s) | Int i -> Some (Int64.of_int i) | _ -> None) xs
         | _ -> []
       in
       let built = Analysis_signature.Observation.build_all tx txid spk_hints utxo_values in
       let ok_obs = List.filter_map (function (_, Ok o) -> Some o | _ -> None) built in
       let records =
         List.mapi
           (fun _i (o : Analysis_signature.Observation.observation) ->
              { Analysis_signature.Sig_analysis.tx_id = o.txid;
                input_index = o.input_index;
                pubkey = Some o.public_key_hex;
                r = o.r;
                s = o.s;
                z = o.z;
                timestamp = None })
           ok_obs
       in
       let result = Analysis_signature.Sig_analysis.analyze records in
       Obj
         [ "ok", Bool true;
           "txid", Str txid;
           "id_derivation", id_info;
           "record_count", Int (List.length records);
           "valid_count", Int (List.length result.signatures);
           "invalid_count", Int (List.length result.invalid);
           "repeated_r_groups", Int (List.length result.repeated_r);
           "repeated_r",
             List
               (List.map
                  (fun (r, sigs) ->
                     Obj
                       [ "r", Json.z r;
                         "count", Int (List.length sigs);
                         "signatures",
                           List
                             (List.map
                                (fun (s : Analysis_signature.Sig_analysis.signature_record) ->
                                   Obj
                                     [ "tx_id", Str s.tx_id;
                                       "input_index", Int s.input_index;
                                       "pubkey", (match s.pubkey with None -> Null | Some p -> Str p);
                                       "r", Json.z s.r;
                                       "s", Json.z s.s;
                                       "z", (match s.z with None -> Null | Some z -> Json.z z) ])
                                sigs) ])
                  result.repeated_r);
           "note",
             Str "Sig_analysis.print_analysis writes to stdout. The structured fields above carry the same information; the console renders them rather than capturing stdout." ])

let ep_pipeline (body : t) : t =
  (* A single call that runs every stage in order.  Mirrors what the live
     Pipeline tab shows, so the UI and the API cannot disagree. *)
  match require_hex body "hex" with
  | Error e -> e
  | Ok raw ->
    (match parse_tx_hex raw with
     | Error e -> e
     | Ok tx ->
       let raw_bytes = optional_hex body "hex" in
       let (txid, id_info) = resolve_ids body tx raw_bytes in

       let stage_parse =
         Obj
           [ "stage", Str "parse";
             "ok", Bool true;
             "input_count", Int (List.length tx.inputs);
             "output_count", Int (List.length tx.outputs);
             "segwit", Bool tx.segwit;
             "transaction", Encode.transaction tx ] in

       let extracted =
         List.mapi (fun i _ -> (i, Signature_extraction.extract_single tx i)) tx.inputs in
       let stage_extract =
         Obj
           [ "stage", Str "extract";
             "ok", Bool true;
             "results",
               List
                 (List.map
                    (fun (i, r) ->
                       Obj
                         [ "input_index", Int i;
                           "result",
                             (match r with
                              | Ok res -> Encode.extraction_result res
                              | Error e -> of_extraction_error e) ])
                    extracted) ] in

       let built = Analysis_signature.Observation.build_all tx txid [] [] in
       let ok_obs = List.filter_map (function (_, Ok o) -> Some o | _ -> None) built in
       let stage_obs =
         Obj
           [ "stage", Str "observation";
             "ok", Bool true;
             "txid", Str txid;
             "observation_count", Int (List.length ok_obs);
             "failed_observations", Int (List.length built - List.length ok_obs);
             "observations",
               List
                 (List.map
                    (fun (i, r) ->
                       Obj
                         [ "input_index", Int i;
                           "result",
                             (match r with
                              | Ok o -> Encode.observation o
                              | Error e -> of_observation_error e) ])
                    built) ] in

       let analyses = Nonce.analyze_transaction txid [ ok_obs ] in
       let stage_nonce =
         Obj
           [ "stage", Str "nonce";
             "ok", Bool true;
             "analyses", List (List.map Encode.input_analysis analyses) ] in

       let stats = Statistics.compute_aggregate_stats [ ok_obs ] in
       let stage_stats =
         Obj [ "stage", Str "statistics"; "ok", Bool true;
               "stats", Encode.aggregate_stats stats ] in

       let critical =
         List.concat_map
           (fun (a : Nonce.input_analysis) ->
              if a.risk_level = "CRITICAL" then [ a.summary ] else [])
           analyses in
       let stage_findings =
         Obj
           [ "stage", Str "findings";
             "ok", Bool true;
             "critical_count", Int (List.length critical);
             "critical_findings", List (List.map (fun s -> Str s) critical) ] in

       Obj
         [ "ok", Bool true;
           "txid", Str txid;
           "id_derivation", id_info;
           "stages",
             List [ stage_parse; stage_extract; stage_obs; stage_nonce; stage_stats; stage_findings ] ])

(* ------------------------------------------------------------------ routing *)

type response = {
  status : int;
  content_type : string;
  body : t;
}

let json_response (body : t) : response =
  { status = 200; content_type = "application/json; charset=utf-8"; body }

let error_response status kind message : response =
  { status; content_type = "application/json; charset=utf-8"; body = error kind message }

(* [inspect] is called for its side effect of timing; the server passes a
   closure so this module stays free of any clock of its own. *)
let with_timing (now : unit -> float) (f : unit -> t) : t =
  let t0 = now () in
  let result = try f () with
    | e ->
      Obj
        [ "ok", Bool false;
          "kind", Str "unhandled_exception";
          "message", Str (Printexc.to_string e) ]
  in
  let t1 = now () in
  Obj
    [ "duration_ms", Float (Float.round ((t1 -. t0) *. 1000.0));
      "result", result ]

let handle ~root ~now (route : string) (body : t) : response =
  let wrapped f = json_response (with_timing now (fun () -> f ())) in
  match route with
  | "GET /api/health" -> json_response (ep_health ~root Null)
  | "GET /api/functions" -> wrapped (fun () -> ep_functions ~root Null)
  | "POST /api/parse" -> wrapped (fun () -> ep_parse body)
  | "POST /api/script/classify" -> wrapped (fun () -> ep_script_classify body)
  | "POST /api/script/parse" -> wrapped (fun () -> ep_script_parse body)
  | "POST /api/der/parse" -> wrapped (fun () -> ep_der_parse body)
  | "POST /api/sighash/legacy" -> wrapped (fun () -> ep_sighash_legacy body)
  | "POST /api/sighash/bip143" -> wrapped (fun () -> ep_sighash_bip143 body)
  | "POST /api/signatures/extract" -> wrapped (fun () -> ep_signatures_extract body)
  | "POST /api/observation/build" -> wrapped (fun () -> ep_observation_build body)
  | "POST /api/nonce/analyze" -> wrapped (fun () -> ep_nonce_analyze body)
  | "POST /api/statistics" -> wrapped (fun () -> ep_statistics body)
  | "POST /api/sig-analysis" -> wrapped (fun () -> ep_sig_analysis body)
  | "POST /api/pipeline" -> wrapped (fun () -> ep_pipeline body)
  | _ ->
    error_response 404 "not_found" (Printf.sprintf "no route for %s" route)

(* Exposed so the server can advertise exactly the routes it implements, and so
   the frontend can compare its own list against this one. *)
let routes : string list =
  [ "GET /api/health";
    "GET /api/functions";
    "POST /api/parse";
    "POST /api/script/classify";
    "POST /api/script/parse";
    "POST /api/der/parse";
    "POST /api/sighash/legacy";
    "POST /api/sighash/bip143";
    "POST /api/signatures/extract";
    "POST /api/observation/build";
    "POST /api/nonce/analyze";
    "POST /api/statistics";
    "POST /api/sig-analysis";
    "POST /api/pipeline" ]
