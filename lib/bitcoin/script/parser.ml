(* lib/bitcoin/script/parser.ml
   Bitcoin Script wire-format parser.

   Design rules:
   - Consumes all bytes in the input buffer (scripts are pre-sliced by the tx
     parser; there is no trailing-byte concept at this layer).
   - Every read is bounds-checked via Bytes_util.
   - Error context strings name the specific field that failed.
   - No execution semantics, no opcode interpretation. *)

(* ------------------------------------------------------------------ cursor *)

type cursor = { buf : bytes; pos : int }

let remaining c = Bytes.length c.buf - c.pos
let advance  c n = { c with pos = c.pos + n }

(* ------------------------------------------------------------------ primitives *)

let read_byte ctx c =
  match Bytes_util.read_byte c.buf c.pos with
  | Error _ -> Error (Common.Parse_error.Truncated ctx)
  | Ok b    -> Ok (b, advance c 1)

let read_u16_le ctx c =
  match Bytes_util.read_u16_le c.buf c.pos with
  | Error _ -> Error (Common.Parse_error.Truncated ctx)
  | Ok v    -> Ok (v, advance c 2)

let read_u32_le ctx c =
  match Bytes_util.read_u32_le c.buf c.pos with
  | Error _ -> Error (Common.Parse_error.Truncated ctx)
  | Ok v    -> Ok (v, advance c 4)

let read_bytes ctx n c =
  if n < 0 then
    Error (Common.Parse_error.Bad_length ctx)
  else if n > Sys.max_string_length then
    Error (Common.Parse_error.Bad_length
             (Printf.sprintf "%s: length %d exceeds platform limit" ctx n))
  else
    match Bytes_util.slice c.buf c.pos n with
    | Error _ -> Error (Common.Parse_error.Truncated ctx)
    | Ok b    -> Ok (b, advance c n)

(* ------------------------------------------------------------------ instruction *)

let parse_one c =
  let ( let* ) = Result.bind in
  let* (op, c) = read_byte "script opcode" c in
  match op with

  (* OP_0 / OP_FALSE: push empty byte vector *)
  | 0x00 ->
    Ok (Script.Push_data { opcode = 0x00; data = Bytes.empty }, c)

  (* Direct push: opcode 0x01..0x4b means "push exactly N bytes" *)
  | n when n >= 0x01 && n <= 0x4b ->
    let* (data, c) = read_bytes (Printf.sprintf "OP_DATA_%d data" n) n c in
    Ok (Script.Push_data { opcode = n; data }, c)

  (* OP_PUSHDATA1: 1-byte LE length, then data *)
  | 0x4c ->
    let* (len, c) = read_byte "OP_PUSHDATA1 length" c in
    let* (data, c) = read_bytes "OP_PUSHDATA1 data" len c in
    Ok (Script.Push_data { opcode = 0x4c; data }, c)

  (* OP_PUSHDATA2: 2-byte LE length, then data *)
  | 0x4d ->
    let* (len, c) = read_u16_le "OP_PUSHDATA2 length" c in
    let* (data, c) = read_bytes "OP_PUSHDATA2 data" len c in
    Ok (Script.Push_data { opcode = 0x4d; data }, c)

  (* OP_PUSHDATA4: 4-byte LE length, then data *)
  | 0x4e ->
    let* (len, c) = read_u32_le "OP_PUSHDATA4 length" c in
    (* Guard: reject lengths that exceed the remaining buffer or platform limit. *)
    if len > remaining c then
      Error (Common.Parse_error.Bad_length
               (Printf.sprintf "OP_PUSHDATA4 data: declared length %d exceeds remaining %d bytes"
                  len (remaining c)))
    else
      let* (data, c) = read_bytes "OP_PUSHDATA4 data" len c in
      Ok (Script.Push_data { opcode = 0x4e; data }, c)

  (* OP_1NEGATE: pushes -1, no following bytes *)
  | 0x4f ->
    Ok (Script.Push_data { opcode = 0x4f; data = Bytes.empty }, c)

  (* OP_1 .. OP_16 (0x51..0x60): push small integers, no following bytes *)
  | n when n >= 0x51 && n <= 0x60 ->
    Ok (Script.Push_data { opcode = n; data = Bytes.empty }, c)

  (* All other opcodes: bare Opcode *)
  | op ->
    Ok (Script.Opcode op, c)

(* ------------------------------------------------------------------ loop *)

let parse_all buf =
  let c = { buf; pos = 0 } in
  let rec loop c acc =
    if remaining c = 0 then Ok (List.rev acc)
    else
      match parse_one c with
      | Error e        -> Error e
      | Ok (instr, c') -> loop c' (instr :: acc)
  in
  loop c []

(* ------------------------------------------------------------------ public API *)

let of_bytes = parse_all

let of_hex h =
  match Hex.to_bytes h with
  | Error e  -> Error e
  | Ok bytes -> of_bytes bytes
