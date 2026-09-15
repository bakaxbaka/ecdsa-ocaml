(* lib/bitcoin/transaction/parser.ml
   Bitcoin transaction wire-format parser.

   Design rules enforced here:
   - CompactSize lives here, not in Bytes_util.
   - The parser is purely functional over an immutable cursor {buf, pos}.
   - Every read advances the cursor by returning a new offset; the original
     buffer is never mutated.
   - Error context strings name the field being read so failures are locatable.
   - Trailing bytes after a complete transaction are an error.
   - Negative output values are rejected.
   - SegWit invariant: when segwit=true, exactly one witness stack per input. *)

(* ------------------------------------------------------------------ cursor *)

(* A cursor is a (buffer, position) pair.  All parse_* functions take a cursor
   and return (value, new_position) or Error. *)
type cursor = {
  buf : bytes;
  pos : int;
}

let cursor_of_bytes buf = { buf; pos = 0 }

let remaining cur = Bytes.length cur.buf - cur.pos

(* ------------------------------------------------------------------ low-level reads *)

(* Read a single byte, advance position. *)
let read_byte ctx cur =
  match Bytes_util.read_byte cur.buf cur.pos with
  | Error _ -> Error (Common.Parse_error.Truncated ctx)
  | Ok b    -> Ok (b, { cur with pos = cur.pos + 1 })

(* Read n bytes as a fresh copy, advance position. *)
let read_bytes ctx n cur =
  if n < 0 then Error (Common.Parse_error.Bad_length ctx)
  else
    match Bytes_util.slice cur.buf cur.pos n with
    | Error _ -> Error (Common.Parse_error.Truncated ctx)
    | Ok b    -> Ok (b, { cur with pos = cur.pos + n })

let read_u32_le ctx cur =
  match Bytes_util.read_u32_le cur.buf cur.pos with
  | Error _ -> Error (Common.Parse_error.Truncated ctx)
  | Ok v    -> Ok (v, { cur with pos = cur.pos + 4 })

let read_u64_le ctx cur =
  match Bytes_util.read_u64_le cur.buf cur.pos with
  | Error _ -> Error (Common.Parse_error.Truncated ctx)
  | Ok v    -> Ok (v, { cur with pos = cur.pos + 8 })

(* ------------------------------------------------------------------ CompactSize *)

(* Decode one CompactSize integer.  Returns (value, new_cursor).
   Enforces canonical (minimal) encoding and platform-addressable range. *)
let read_compact_size ctx cur =
  match read_byte ctx cur with
  | Error e -> Error e
  | Ok (first, cur1) ->
    match first with
    | n when n <= 0xFC ->
      Ok (n, cur1)

    | 0xFD ->
      (* 2-byte LE uint16; value must be >= 0xFD *)
      (match Bytes_util.read_u16_le cur1.buf cur1.pos with
       | Error _ -> Error (Common.Parse_error.Truncated ctx)
       | Ok v ->
         if v < 0xFD then
           Error (Common.Parse_error.Non_canonical
                    (Printf.sprintf "%s: CompactSize 0xFD used for value %d" ctx v))
         else Ok (v, { cur1 with pos = cur1.pos + 2 }))

    | 0xFE ->
      (* 4-byte LE uint32; value must be >= 0x1_0000 *)
      (match Bytes_util.read_u32_le cur1.buf cur1.pos with
       | Error _ -> Error (Common.Parse_error.Truncated ctx)
       | Ok v ->
         if v < 0x1_0000 then
           Error (Common.Parse_error.Non_canonical
                    (Printf.sprintf "%s: CompactSize 0xFE used for value %d" ctx v))
         else if v > Sys.max_string_length then
           Error (Common.Parse_error.Bad_length
                    (Printf.sprintf "%s: CompactSize value %d exceeds platform limit" ctx v))
         else Ok (v, { cur1 with pos = cur1.pos + 4 }))

    | 0xFF ->
      (* 8-byte LE uint64; value must be >= 0x1_0000_0000 *)
      (match Bytes_util.read_u64_le cur1.buf cur1.pos with
       | Error _ -> Error (Common.Parse_error.Truncated ctx)
       | Ok v64 ->
         let threshold = 0x1_0000_0000L in
         if Int64.compare v64 threshold < 0 then
           Error (Common.Parse_error.Non_canonical
                    (Printf.sprintf "%s: CompactSize 0xFF used for value %Ld" ctx v64))
         else
           (* Reject values that can't be used as an OCaml array/buffer index. *)
           let max_v = Int64.of_int Sys.max_string_length in
           if Int64.compare v64 max_v > 0 then
             Error (Common.Parse_error.Bad_length
                      (Printf.sprintf "%s: CompactSize value %Ld exceeds platform limit" ctx v64))
           else Ok (Int64.to_int v64, { cur1 with pos = cur1.pos + 8 }))

    | _ ->
      (* Unreachable: first byte is 0..0xFF, all cases covered above. *)
      assert false

(* ------------------------------------------------------------------ outpoint *)

let parse_outpoint cur =
  let ( let* ) = Result.bind in
  let* (txid_bytes, cur) = read_bytes "outpoint.txid" 32 cur in
  let* (vout,       cur) = read_u32_le "outpoint.vout" cur in
  Ok ({ Types.txid = txid_bytes; vout }, cur)

(* ------------------------------------------------------------------ input *)

let parse_input cur =
  let ( let* ) = Result.bind in
  let* (previous_output, cur) = parse_outpoint cur in
  let* (script_len,      cur) = read_compact_size "input.script_sig length" cur in
  let* (script_sig,      cur) = read_bytes "input.script_sig" script_len cur in
  let* (sequence,        cur) = read_u32_le "input.sequence" cur in
  Ok ({ Types.previous_output; script_sig; sequence }, cur)

(* ------------------------------------------------------------------ output *)

let parse_output cur =
  let ( let* ) = Result.bind in
  let* (value, cur) = read_u64_le "output.value" cur in
  (* Reject negative values — wire format is unsigned but Int64 is signed. *)
  if Int64.compare value Int64.zero < 0 then
    Error (Common.Parse_error.Bad_length
             (Printf.sprintf "output.value: negative value %Ld" value))
  else
    let* (script_len,    cur) = read_compact_size "output.script_pubkey length" cur in
    let* (script_pubkey, cur) = read_bytes "output.script_pubkey" script_len cur in
    Ok ({ Types.value; script_pubkey }, cur)

(* ------------------------------------------------------------------ witness stack *)

(* One witness stack: varint item count, then for each item: varint len + bytes. *)
let parse_witness_stack cur =
  let ( let* ) = Result.bind in
  let* (item_count, cur) = read_compact_size "witness.item_count" cur in
  let rec loop i acc cur =
    if i = 0 then Ok (List.rev acc, cur)
    else
      let* (len,  cur) = read_compact_size "witness.item_length" cur in
      let* (item, cur) = read_bytes "witness.item" len cur in
      loop (i - 1) (item :: acc) cur
  in
  loop item_count [] cur

(* ------------------------------------------------------------------ repeated parsers *)

(* Parse [count] items using [parse_one], return list and final cursor. *)
let parse_list count parse_one ctx cur =
  let ( let* ) = Result.bind in
  let rec loop i acc cur =
    if i = 0 then Ok (List.rev acc, cur)
    else
      let* (item, cur) = parse_one cur in
      loop (i - 1) (item :: acc) cur
  in
  if count = 0 then
    Error (Common.Parse_error.Bad_length
             (Printf.sprintf "%s: count is zero" ctx))
  else
    let* _ = Ok () in
    loop count [] cur

(* ------------------------------------------------------------------ transaction *)

let parse_transaction cur =
  let ( let* ) = Result.bind in

  (* version: int32 LE *)
  let* (version, cur) = read_u32_le "transaction.version" cur in
  (* Store as signed int — version is technically int32 on the wire *)
  let version =
    if version land 0x8000_0000 <> 0
    then version - 0x1_0000_0000   (* sign-extend *)
    else version
  in

  (* SegWit detection: peek at the next two bytes.
     If byte[0]=0x00 and byte[1]≥0x01, this is a SegWit transaction.
     The marker/flag bytes are consumed; the input count follows. *)
  let* (segwit, cur) =
    if remaining cur >= 2
       && Char.code (Bytes.get cur.buf cur.pos)       = 0x00
       && Char.code (Bytes.get cur.buf (cur.pos + 1)) >= 0x01
    then
      let flag = Char.code (Bytes.get cur.buf (cur.pos + 1)) in
      if flag <> 0x01 then
        (* BIP144 requires flag=0x01; reject unknown flags. *)
        Error (Common.Parse_error.Non_canonical
                 (Printf.sprintf "transaction: unknown segwit flag 0x%02x" flag))
      else
        Ok (true, { cur with pos = cur.pos + 2 })
    else
      Ok (false, cur)
  in

  (* vin count *)
  let* (vin_count, cur) = read_compact_size "transaction.vin_count" cur in

  (* inputs *)
  let* (inputs, cur) = parse_list vin_count parse_input "transaction.inputs" cur in

  (* vout count *)
  let* (vout_count, cur) = read_compact_size "transaction.vout_count" cur in

  (* outputs *)
  let* (outputs, cur) = parse_list vout_count parse_output "transaction.outputs" cur in

  (* witness data (SegWit only) *)
  let* (witnesses, cur) =
    if segwit then begin
      (* One witness stack per input, in the same order. *)
      let rec loop i acc cur =
        if i = 0 then Ok (List.rev acc, cur)
        else
          let* (stack, cur) = parse_witness_stack cur in
          loop (i - 1) (stack :: acc) cur
      in
      loop vin_count [] cur
    end else
      Ok ([], cur)
  in

  (* lock_time: uint32 LE *)
  let* (lock_time, cur) = read_u32_le "transaction.lock_time" cur in

  Ok ({ Types.version; inputs; outputs; witnesses; lock_time; segwit }, cur)

(* ------------------------------------------------------------------ public API *)

let of_bytes buf =
  let cur = cursor_of_bytes buf in
  match parse_transaction cur with
  | Error e -> Error e
  | Ok (tx, cur) ->
    if remaining cur > 0 then
      Error (Common.Parse_error.Trailing_data
               (Printf.sprintf "transaction: %d trailing bytes" (remaining cur)))
    else
      Ok tx

let of_hex h =
  match Hex.to_bytes h with
  | Error e  -> Error e
  | Ok bytes -> of_bytes bytes
