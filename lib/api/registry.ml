(* lib/api/registry.ml
   The function catalogue, derived from the source interfaces.

   The catalogue is built by parsing the project's [.mli] files rather than
   being written by hand.  A hand-maintained list would drift from the code the
   moment someone adds a function; this cannot, because the interfaces *are* the
   source of truth.

   {1 What it parses}

   - [val name : type]           — a function or value
   - [type name = ...]           — a type declaration
   - [module Name : sig]         — a submodule (and its own declarations)
   - [include module type of X]  — recorded as an alias, so a module that has no
                                   [val]s of its own is not reported as empty

   That last case matters: [tx_parser.mli] is a single [include], and [field]
   and [scalar] expose everything through a [module T].  A parser that only
   matched [^val] would report all three as empty and the UI would show three
   blank libraries.

   {1 Attached documentation}

   A declaration's doc comment is the [** ... *] block immediately above it,
   with no blank line in between.  That is the convention these interfaces
   already follow, so the catalogue gets real descriptions for free. *)

(* ------------------------------------------------------------------ types *)

type kind =
  | Val
  | Type_decl
  | Module_decl
  | Include

let kind_to_string = function
  | Val -> "val"
  | Type_decl -> "type"
  | Module_decl -> "module"
  | Include -> "include"

type decl = {
  kind : kind;
  name : string;
  signature : string;          (* the full declaration text, whitespace-collapsed *)
  doc : string option;
  file : string;               (* path relative to the project root *)
  line : int;
}

type module_info = {
  module_name : string;
  library : string;            (* the dune library that provides it *)
  file : string;
  doc : string option;
  decls : decl list;
}

(* ------------------------------------------------------------------ help text *)

(* A short, honest description of what each module is for.  Keyed by module
   name; a module with no entry simply carries no module-level doc, which the
   UI renders as absent rather than inventing something. *)
let module_blurb name =
  match name with
  | "Types" -> Some "Bitcoin transaction domain types: inputs, outputs, witnesses, txid helpers."
  | "Tx_parser" -> Some "Bitcoin P2P wire-format transaction parser (legacy and SegWit)."
  | "Parser" -> Some "Bitcoin Script wire-format parser."
  | "Script" -> Some "Bitcoin Script instruction type and opcode constants."
  | "Classify" -> Some "Structural scriptPubKey classifier (P2PKH, P2WPKH, P2TR, ...)."
  | "Legacy" -> Some "Legacy (pre-SegWit) signature hash computation."
  | "Bip143" -> Some "BIP143 SegWit v0 signature hash computation."
  | "Signature_extraction" -> Some "Extracts ECDSA signatures from scriptSig and witness stacks."
  | "Observation" -> Some "Builds a fully resolved observation (r, s, z, pubkey, validity) per input."
  | "Sig_analysis" -> Some "Signature pattern analysis and nonce-reuse detection over CSV input."
  | "Nonce" -> Some "Nonce relationship analysis: reuse, related nonces, risk scoring."
  | "Statistics" -> Some "Aggregate statistics across observations."
  | "Analysis" -> Some "Top-level pipeline: observation building, nonce analysis, statistics."
  | "Der" -> Some "Strict Bitcoin DER signature parser with appended sighash byte."
  | "Signature" -> Some "ECDSA signature operations and scalar range validation."
  | "Verify" -> Some "ECDSA signature verification."
  | "Point" -> Some "secp256k1 curve point arithmetic and SEC1 encoding."
  | "Field" -> Some "Prime field arithmetic modulo the secp256k1 field prime."
  | "Scalar" -> Some "Scalar arithmetic modulo the secp256k1 group order."
  | "Hash" -> Some "SHA-256 and Bitcoin double-SHA-256."
  | "Ripemd160" -> Some "Pure OCaml RIPEMD-160."
  | "Hex" -> Some "Hex encoding and decoding."
  | "Bytes_util" -> Some "Bounds-checked byte readers for parsers."
  | "Error" -> Some "The four error families, one per layer boundary."
  | "Nonce_checker" -> Some "Streaming repeated-nonce detection over a sequence of transactions."
  | "Transaction_analysis" -> Some "Simplified transaction stand-in for the streaming nonce checker."
  | "Network" -> Some "Bitcoin network parameters (mainnet, testnet, regtest)."
  | _ -> None

(* ------------------------------------------------------------------ parsing *)

let is_blank s =
  let s = String.trim s in
  s = "" || s = "(**" || s = "*)"

(* Leading indentation width, used to detect continuation lines. *)
let indent_of s =
  let n = ref 0 in
  (try
     while !n < String.length s && (s.[!n] = ' ' || s.[!n] = '\t') do incr n done
   with _ -> ());
  !n

(* Collapse a multi-line declaration into one line, preserving structure. *)
let collapse lines =
  let joined =
    List.map String.trim lines |> String.concat " "
  in
  (* Collapse runs of whitespace without touching string literals in a way that
     matters for display. *)
  let buf = Buffer.create (String.length joined) in
  let prev_space = ref false in
  String.iter
    (fun c ->
       if c = ' ' || c = '\t' then begin
         if not !prev_space then Buffer.add_char buf ' ';
         prev_space := true
       end else begin
         Buffer.add_char buf c;
         prev_space := false
       end)
    joined;
  Buffer.contents buf

(* Strip the comment markers and any leading [*] from a doc block.

   Written to be robust to HOW the line arrived here rather than assuming a
   particular call path. An earlier version stripped the closing marker but left
   the opening one attached, so single-line blocks reached the catalogue — and
   therefore /api/functions and the UI — with the opening marker still glued to
   the text. Repeated attempts to patch the individual branches kept moving the
   bug rather than removing it, because the same text can reach here either as a
   full line or already partially unwrapped. Stripping both markers
   unconditionally, in either order, removes the whole class of error.

   NOTE for editors: the literal marker characters must not be written inside
   this comment. OCaml comments nest, so an opening marker here opens a second
   comment level and swallows the remainder of the file. Spell them out instead.

   test/unit/api/test_registry.ml asserts that no doc string contains the opening
   marker or ends with the closing one; that assertion is what surfaced this. *)

let clean_doc lines =
  let drop_suffix s suf =
    let n = String.length s and m = String.length suf in
    if m > 0 && n >= m && String.sub s (n - m) m = suf then String.sub s 0 (n - m)
    else s
  in
  let drop_prefix s pfx =
    let n = String.length s and m = String.length pfx in
    if m > 0 && n >= m && String.sub s 0 m = pfx then String.sub s m (n - m)
    else s
  in
  let strip l =
    let l = String.trim l in
    (* Closing marker first, so the left edge is clean for the opener test. *)
    let l = drop_suffix l "*)" |> String.trim in
    let l = drop_prefix l "(**" |> String.trim in
    (* A continuation line such as "   * more text" keeps its leading star. *)
    let l = if String.length l > 0 && l.[0] = '*' then drop_prefix l "*" |> String.trim else l in
    l
  in
  match List.map strip (List.filter (fun l -> not (is_blank l)) lines) with
  | [] -> None
  | xs -> Some (String.concat " " xs)

let starts_decl l =
  let t = String.trim l in
  let has p = String.length t >= String.length p && String.sub t 0 (String.length p) = p in
  has "val " || has "type " || has "module " || has "include " || has "end"

(* Split a declaration's name and the rest of its text. *)
let split_name t =
  match String.index_opt t ' ' with
  | None -> (t, "")
  | Some i ->
    let rest = String.sub t (i + 1) (String.length t - i - 1) in
    (* Strip a trailing separator or annotation so only the bare name remains. *)
    let name =
      match String.index_opt rest ':' with
      | Some j -> String.sub rest 0 j
      | None ->
        (match String.index_opt rest '=' with
         | Some j -> String.sub rest 0 j
         | None -> rest)
    in
    (String.trim name, String.trim rest)

let parse_mli ~root ~library ~file : module_info =
  let path = Filename.concat root file in
  let ic = open_in_bin path in
  let n = in_channel_length ic in
  let content = really_input_string ic n in
  close_in ic;

  let lines = String.split_on_char '\n' content in
  let lines = List.map (fun l -> if String.length l > 0 && l.[String.length l - 1] = '\r'
                                 then String.sub l 0 (String.length l - 1) else l) lines in

  let module_name = Filename.remove_extension (Filename.basename file) in
  (* Interfaces name the module in lowercase for the filename; derive the OCaml
     module name by capitalising the first letter. *)
  let module_name = String.capitalize_ascii module_name in

  let header_doc = ref [] in
  let in_header = ref true in
  let pending_doc = ref [] in
  let acc = ref [] in
  let lineno = ref 0 in

  let arr = Array.of_list lines in
  let total = Array.length arr in
  let i = ref 0 in

  while !i < total do
    let line = arr.(!i) in
    lineno := !i + 1;
    let t = String.trim line in

    (* [was_header] and [just_left_header] matter because the transition out of the
       header happens on a line that is itself a declaration. Without tracking the
       transition, the same iteration would run both the header branch and the
       body branch, and the body branch's "not a doc block" path would clear the
       [pending_doc] the header branch had just set. *)
    let was_header = !in_header in
    let just_left_header = was_header && starts_decl line in

    if was_header && not just_left_header then
      header_doc := line :: !header_doc
    else if just_left_header then begin
      in_header := false;
      (* A doc block at the very top of a file normally describes the module, and
         is recorded as such. But when a declaration follows it with no blank line
         in between, the block is also that declaration's doc — which is how
         single-function interfaces are written:

           (** RIPEMD-160. *)
           val hash : bytes -> bytes

         Without this, such a declaration reaches the catalogue with no
         description at all. The last accumulated header line is [List.hd], so a
         blank separator shows up as "" and is correctly not carried over. *)
      (match !header_doc with
       | last :: _ when String.trim last <> "" -> pending_doc := List.rev !header_doc
       | _ -> ())
    end;

    if (not was_header) || just_left_header then begin
      if String.length t >= 3 && String.sub t 0 3 = "(**" then begin
        (* Accumulate a doc block, including multi-line blocks. *)
        let blk = ref [ line ] in
        let closed = ref (String.length t >= 4 && String.sub t (String.length t - 2) 2 = "*)") in
        while not !closed && !i + 1 < total do
          incr i;
          let l2 = arr.(!i) in
          blk := l2 :: !blk;
          let t2 = String.trim l2 in
          if String.length t2 >= 2 && String.sub t2 (String.length t2 - 2) 2 = "*)" then
            closed := true
        done;
        pending_doc := List.rev !blk
      end
      else if is_blank line then begin
        (* A blank line detaches a pending doc block. *)
        if !pending_doc <> [] then pending_doc := []
      end
      else begin
        let is_val = String.length t >= 4 && String.sub t 0 4 = "val " in
        let is_type = String.length t >= 5 && String.sub t 0 5 = "type " in
        let is_mod = String.length t >= 7 && String.sub t 0 7 = "module " in
        let is_inc = String.length t >= 8 && String.sub t 0 8 = "include " in

        if is_val || is_type || is_mod || is_inc then begin
          (* Collect continuation lines: those indented deeper than the keyword. *)
          let base_indent = indent_of line in
          let decl_lines = ref [ line ] in
          let j = ref !i in
          let stop = ref false in
          while not !stop && !j + 1 < total do
            let nxt = arr.(!j + 1) in
            let nt = String.trim nxt in
            if is_blank nxt then stop := true
            else if starts_decl nxt && indent_of nxt <= base_indent then stop := true
            else if String.length nt >= 3 && String.sub nt 0 3 = "(**" then stop := true
            else if indent_of nxt > base_indent then begin
              decl_lines := nxt :: !decl_lines;
              incr j
            end else begin
              (* Same indent but not a new declaration: treat as continuation. *)
              decl_lines := nxt :: !decl_lines;
              incr j
            end
          done;

          let text = collapse (List.rev !decl_lines) in
          let kind =
            if is_val then Val
            else if is_type then Type_decl
            else if is_mod then Module_decl
            else Include
          in
          (* For [include], the whole text is the interesting part. *)
          let name =
            if kind = Include then text
            else fst (split_name t)
          in
          acc :=
            { kind; name; signature = text;
              doc = clean_doc !pending_doc;
              file; line = !lineno }
            :: !acc;
          pending_doc := [];
          i := !j
        end
        else begin
          pending_doc := []
        end
      end
    end;
    incr i
  done;

  { module_name;
    library;
    file;
    doc = clean_doc (List.rev !header_doc);
    decls = List.rev !acc }

(* ------------------------------------------------------------------ discovery *)

(* The libraries declared in the dune files, mapped to the directories whose
   .mli files they own.  Kept explicit: dune's own scoping rules are not
   something we want to re-implement badly here. *)
let library_of_relpath rel =
  let starts p = String.length rel >= String.length p && String.sub rel 0 (String.length p) = p in
  if starts "lib/api/" then "api"
  else if starts "lib/common/" then "common"
  else if starts "lib/crypto/encoding/" then "encoding"
  else if starts "lib/crypto/hash/" then "hash"
  else if starts "lib/crypto/field/" then "field"
  else if starts "lib/crypto/scalar/" then "scalar"
  else if starts "lib/crypto/curve/" then "curve"
  else if starts "lib/crypto/ecdsa/" then "ecdsa_der"
  else if starts "lib/bitcoin/transaction/" then "bitcoin_tx"
  else if starts "lib/bitcoin/script/" then "script_types"
  else if starts "lib/bitcoin/sighash/" then "sighash"
  else if starts "lib/bitcoin/" then "bitcoin"
  else if starts "lib/analysis/signature/" then "analysis_signature"
  else if starts "lib/analysis/nonce/" then "analysis_nonce"
  else if starts "lib/analysis/statistics/" then "analysis_statistics"
  else if starts "lib/analysis/" then "analysis"
  else if starts "lib/tx_stream/" then "tx_stream"
  else if starts "lib/application/" then "application"
  else "other"

let rec walk (dir : string) (rel : string) (acc : string list ref) =
  let full = if rel = "" then dir else Filename.concat dir rel in
  match Sys.readdir full with
  | exception _ -> ()
  | entries ->
    Array.iter
      (fun e ->
         let child = if rel = "" then e else rel ^ "/" ^ e in
         let child_full = Filename.concat dir child in
         if Sys.is_directory child_full then begin
           (* Skip build output and vendored trees. *)
           if e <> "_build" && e <> ".git" && e <> "node_modules" then
             walk dir child acc
         end
         else if Filename.check_suffix e ".mli" then
           acc := child :: !acc)
      entries

let scan ~root : module_info list =
  let acc = ref [] in
  walk root "lib" acc;
  let files = List.sort compare !acc in
  List.map
    (fun rel -> parse_mli ~root ~library:(library_of_relpath rel) ~file:rel)
    files

(* ------------------------------------------------------------------ summary *)

let count_decls (ms : module_info list) : int =
  List.fold_left
    (fun a m ->
       a + List.length (List.filter (fun d -> d.kind = Val || d.kind = Module_decl) m.decls))
    0 ms

(* ------------------------------------------------------------------ json *)

let to_json (ms : module_info list) : Json.t =
  let decl_json (d : decl) : Json.t =
    Json.Obj
      [ "kind", Json.Str (kind_to_string d.kind);
        "name", Json.Str d.name;
        "signature", Json.Str d.signature;
        "doc", (match d.doc with None -> Json.Null | Some s -> Json.Str s);
        "file", Json.Str d.file;
        "line", Json.Int d.line ]
  in
  let mod_json (m : module_info) : Json.t =
    let blurb = module_blurb m.module_name in
    Json.Obj
      [ "module", Json.Str m.module_name;
        "library", Json.Str m.library;
        "file", Json.Str m.file;
        "doc",
          Json.(match m.doc with
                | Some s -> Str s
                | None -> (match blurb with Some b -> Str b | None -> Null));
        "decl_count", Json.Int (List.length m.decls);
        "decls", Json.List (List.map decl_json m.decls) ]
  in
  Json.Obj
    [ "modules", Json.List (List.map mod_json ms);
      "module_count", Json.Int (List.length ms);
      "declaration_count", Json.Int (count_decls ms) ]
