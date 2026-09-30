(* lib/api/json.ml
   A dependency-free JSON value type and serialiser.

   Deliberately hand-rolled rather than using Yojson: lib/api already depends on
   nearly every library in the project, and every extra dependency is another
   thing that can break the build on this Windows switch.

   {1 No truncation}

   Serialisation never shortens a value. Strings are escaped, not clipped; there
   are no length caps and no ellipses anywhere in this module. A consumer that
   wants a shorter view must shorten the value itself, and must say so. *)

type t =
  | Null
  | Bool of bool
  | Int of int
  | Float of float
  | Str of string
  | List of t list
  | Obj of (string * t) list

(* ------------------------------------------------------------------ escaping *)

let add_escaped buf s =
  Buffer.add_char buf '"';
  String.iter
    (fun c ->
       match c with
       | '"'  -> Buffer.add_string buf "\\\""
       | '\\' -> Buffer.add_string buf "\\\\"
       | '\n' -> Buffer.add_string buf "\\n"
       | '\r' -> Buffer.add_string buf "\\r"
       | '\t' -> Buffer.add_string buf "\\t"
       | '\b' -> Buffer.add_string buf "\\b"
       | '\012' -> Buffer.add_string buf "\\f"
       | c ->
         let code = Char.code c in
         (* Control characters must be escaped; everything else is passed
            through as-is so that UTF-8 is preserved byte for byte. *)
         if code < 0x20 then Buffer.add_string buf (Printf.sprintf "\\u%04x" code)
         else Buffer.add_char buf c)
    s;
  Buffer.add_char buf '"'

(* [float] rendering that round-trips and never produces "nan"/"inf", which are
   not valid JSON. Non-finite values become [null] with a companion flag rather
   than silently becoming a number the client would misread. *)
let float_to_string f =
  if Float.is_nan f || Float.is_infinite f then "null"
  else if Float.is_integer f && Float.abs f < 1e15 then
    Printf.sprintf "%.1f" f
  else Printf.sprintf "%.17g" f

let rec write buf = function
  | Null -> Buffer.add_string buf "null"
  | Bool b -> Buffer.add_string buf (if b then "true" else "false")
  | Int i -> Buffer.add_string buf (string_of_int i)
  | Float f -> Buffer.add_string buf (float_to_string f)
  | Str s -> add_escaped buf s
  | List xs ->
    Buffer.add_char buf '[';
    List.iteri
      (fun i x -> if i > 0 then Buffer.add_char buf ','; write buf x)
      xs;
    Buffer.add_char buf ']'
  | Obj fields ->
    Buffer.add_char buf '{';
    List.iteri
      (fun i (k, v) ->
         if i > 0 then Buffer.add_char buf ',';
         add_escaped buf k;
         Buffer.add_char buf ':';
         write buf v)
      fields;
    Buffer.add_char buf '}'

let to_string (v : t) : string =
  let buf = Buffer.create 4096 in
  write buf v;
  Buffer.contents buf

(* ------------------------------------------------------------------ builders *)

let obj fields = Obj fields
let list xs = List xs
let str s = Str s
let int i = Int i
let bool_ b = Bool b

(* Omit a field entirely when it is [None]. Callers that need to distinguish
   "absent" from "null" must handle it themselves; this keeps responses free of
   meaningless nulls. *)
let opt f = function None -> Null | Some v -> f v

let opt_endpoint f = function None -> Null | Some v -> f v

(* ------------------------------------------------------------------ domain primitives *)

(** A big integer, carried as BOTH decimal and zero-padded hex.

    This matters: JavaScript numbers lose precision above 2^53, and every value
    in this codebase routinely exceeds that. Sending a bare number would
    silently corrupt the value on the client, so we never do. *)
let z (v : Z.t) : t =
  let dec = Z.to_string v in
  let hexv =
    if Z.sign v < 0 then "-" ^ Z.format "%x" (Z.neg v)
    else Z.format "%064x" v
  in
  Obj [ "dec", Str dec; "hex", Str hexv; "bits", Int (Z.numbits v) ]

(** Byte strings are carried as hex, with the length always stated so a client
    can verify it received everything. *)
let bytes (b : bytes) : t =
  Obj [ "hex", Str (Hex.of_bytes b); "len", Int (Bytes.length b) ]

let bytes_opt = function None -> Null | Some b -> bytes b

(** A numbers-as-text label, e.g. a sighash byte. *)
let hex_byte (b : int) : string = Printf.sprintf "0x%02x" b

(* ------------------------------------------------------------------ errors *)

let of_parse_error (e : Common.Parse_error.t) : t =
  Obj [ "kind", Str "parse_error"; "message", Str (Common.Parse_error.to_string e) ]

let of_der_error (e : Common.Der_error.t) : t =
  Obj [ "kind", Str "der_error"; "message", Str (Common.Der_error.to_string e) ]

let of_extraction_error (e : Signature_extraction.error) : t =
  Obj
    [ "kind", Str "extraction_error";
      "message", Str (Signature_extraction.error_to_string e) ]

let of_observation_error (e : Analysis_signature.Observation.error) : t =
  Obj
    [ "kind", Str "observation_error";
      "message", Str (Analysis_signature.Observation.error_to_string e) ]

(* ------------------------------------------------------------------ parsing *)

(* A small recursive-descent JSON reader, the counterpart to [to_string].
   It exists so request bodies can be parsed without adding a dependency.

   It accepts a superset of strict JSON in one respect that matters here: a
   bare hex string with no surrounding quotes is rejected (correctly), but
   leading "0x" and mixed case in hex are handled by the callers, not here. *)

exception Parse_fail of string

let parse (s : string) : (t, string) result =
  let pos = ref 0 in
  let n = String.length s in
  let fail msg = raise (Parse_fail (Printf.sprintf "%s at offset %d" msg !pos)) in
  let advance () = incr pos in
  let skip_ws () =
    let continue = ref true in
    while !continue do
      if !pos < n then
        match s.[!pos] with
        | ' ' | '\t' | '\n' | '\r' -> incr pos
        | _ -> continue := false
      else continue := false
    done
  in
  let expect c =
    if !pos < n && s.[!pos] = c then advance ()
    else fail (Printf.sprintf "expected '%c'" c)
  in
  let parse_string () =
    expect '"';
    let buf = Buffer.create 32 in
    let rec loop () =
      if !pos >= n then fail "unterminated string";
      let c = s.[!pos] in
      if c = '"' then advance ()
      else if c = '\\' then begin
        advance ();
        if !pos >= n then fail "unterminated escape";
        let e = s.[!pos] in
        advance ();
        (match e with
         | '"' -> Buffer.add_char buf '"'
         | '\\' -> Buffer.add_char buf '\\'
         | '/' -> Buffer.add_char buf '/'
         | 'n' -> Buffer.add_char buf '\n'
         | 'r' -> Buffer.add_char buf '\r'
         | 't' -> Buffer.add_char buf '\t'
         | 'b' -> Buffer.add_char buf '\b'
         | 'f' -> Buffer.add_char buf '\012'
         | 'u' ->
           if !pos + 4 > n then fail "truncated \\u escape";
           let hexs = String.sub s !pos 4 in
           pos := !pos + 4;
           let code =
             try int_of_string ("0x" ^ hexs) with _ -> fail "invalid \\u escape"
           in
           (* Encode the code point back to UTF-8 so the round trip is stable. *)
           if code < 0x80 then Buffer.add_char buf (Char.chr code)
           else if code < 0x800 then begin
             Buffer.add_char buf (Char.chr (0xC0 lor (code lsr 6)));
             Buffer.add_char buf (Char.chr (0x80 lor (code land 0x3F)))
           end else begin
             Buffer.add_char buf (Char.chr (0xE0 lor (code lsr 12)));
             Buffer.add_char buf (Char.chr (0x80 lor ((code lsr 6) land 0x3F)));
             Buffer.add_char buf (Char.chr (0x80 lor (code land 0x3F)))
           end
         | _ -> fail "invalid escape");
        loop ()
      end else begin
        Buffer.add_char buf c;
        advance ();
        loop ()
      end
    in
    loop ();
    Buffer.contents buf
  in
  let parse_number () =
    let start = !pos in
    if !pos < n && (s.[!pos] = '-' || s.[!pos] = '+') then advance ();
    let is_digit c = c >= '0' && c <= '9' in
    let saw_dot = ref false in
    let continue = ref true in
    while !continue do
      if !pos < n then begin
        let c = s.[!pos] in
        if is_digit c then advance ()
        else if (c = '.' || c = 'e' || c = 'E' || c = '-' || c = '+') && c = '.' && not !saw_dot then begin
          saw_dot := true; advance ()
        end
        else if c = 'e' || c = 'E' || c = '-' || c = '+' then advance ()
        else continue := false
      end else continue := false
    done;
    let text = String.sub s start (!pos - start) in
    (* An empty token is not a number.  Without this check, input such as
       {"a":} fell through to [float_of_string ""], whose Failure was
       swallowed by the [with _] below, so a malformed value silently became the
       empty string instead of a parse error.  That is the worst kind of parser
       bug: it accepts bad input and returns a plausible value. *)
    if text = "" then fail "expected a value";
    if !saw_dot then
      (try Float (float_of_string text) with _ -> fail "invalid number")
    else
      match int_of_string_opt text with
      | Some i -> Int i
      | None ->
        (* Integers beyond OCaml's native range: keep every digit rather than
           silently rounding.  The client sees the exact text. *)
        (try Float (float_of_string text) with _ -> Str text)
  in
  let rec parse_value () =
    skip_ws ();
    if !pos >= n then fail "unexpected end of input";
    match s.[!pos] with
    | '{' ->
      advance ();
      skip_ws ();
      if !pos < n && s.[!pos] = '}' then (advance (); Obj [])
      else begin
        let fields = ref [] in
        let continue = ref true in
        while !continue do
          skip_ws ();
          let k = parse_string () in
          skip_ws ();
          expect ':';
          let v = parse_value () in
          fields := (k, v) :: !fields;
          skip_ws ();
          if !pos < n && s.[!pos] = ',' then advance ()
          else begin
            expect '}';
            continue := false
          end
        done;
        Obj (List.rev !fields)
      end
    | '[' ->
      advance ();
      skip_ws ();
      if !pos < n && s.[!pos] = ']' then (advance (); List [])
      else begin
        let items = ref [] in
        let continue = ref true in
        while !continue do
          let v = parse_value () in
          items := v :: !items;
          skip_ws ();
          if !pos < n && s.[!pos] = ',' then advance ()
          else begin
            expect ']';
            continue := false
          end
        done;
        List (List.rev !items)
      end
    | '"' -> Str (parse_string ())
    | 't' ->
      if !pos + 4 <= n && String.sub s !pos 4 = "true" then (pos := !pos + 4; Bool true)
      else fail "invalid literal"
    | 'f' ->
      if !pos + 5 <= n && String.sub s !pos 5 = "false" then (pos := !pos + 5; Bool false)
      else fail "invalid literal"
    | 'n' ->
      if !pos + 4 <= n && String.sub s !pos 4 = "null" then (pos := !pos + 4; Null)
      else fail "invalid literal"
    | _ -> parse_number ()
  in
  match parse_value () with
  | v ->
    skip_ws ();
    if !pos <> n then Error (Printf.sprintf "trailing data at offset %d" !pos)
    else Ok v
  | exception Parse_fail m -> Error m

(* ------------------------------------------------------------------ accessors *)

let member key = function
  | Obj fields -> List.assoc_opt key fields
  | _ -> None

let as_string = function Str s -> Some s | _ -> None
let as_int = function Int i -> Some i | Float f -> Some (int_of_float f) | _ -> None
let as_list = function List xs -> Some xs | _ -> None

(* ------------------------------------------------------------------ hashes *)

(** Interpret a byte string as a big-endian unsigned integer.

    This is what a Bitcoin hash or a DER integer means.  Stdlib's [Z.of_bits]
    is NOT this: it reads little-endian, so using it on a hash silently reverses
    the value while still producing a plausible-looking number. *) 
let z_of_bytes_be (b : bytes) : Z.t =
  let acc = ref Z.zero in
  for i = 0 to Bytes.length b - 1 do
    acc := Z.add (Z.shift_left !acc 8) (Z.of_int (Char.code (Bytes.get b i)))
  done;
  !acc

let z_of_string_be (s : string) : Z.t = z_of_bytes_be (Bytes.of_string s)
