(* lib/crypto/encoding/bytes_util.ml
   Generic byte-buffer utilities.

   Design rules enforced here:
   - No Bitcoin-specific concepts (VarInt, scripts, hash types, …).
   - All fallible operations return (_, Common.Parse_error.t) result.
   - Integers are decoded/encoded via explicit byte-order helpers so callers
     never need to reason about host endianness.
   - [slice] always copies so the caller owns the returned bytes. *)

(* ------------------------------------------------------------------ helpers *)

(* Check that [off] through [off + need - 1] are valid indices into [buf].
   Returns [Error (Truncated ctx)] when the buffer is too short. *)
let check_bounds buf off need ctx =
  if off < 0 || need < 0 || off + need > Bytes.length buf then
    Error (Common.Parse_error.Truncated ctx)
  else
    Ok ()

(* ------------------------------------------------------------------ reads *)

let read_byte buf off =
  match check_bounds buf off 1 "read_byte" with
  | Error e -> Error e
  | Ok () -> Ok (Char.code (Bytes.get buf off))

(* Little-endian: byte at [off] is the least-significant byte. *)
let read_u16_le buf off =
  match check_bounds buf off 2 "read_u16_le" with
  | Error e -> Error e
  | Ok () ->
    let b0 = Char.code (Bytes.get buf  off)      in   (* LSB *)
    let b1 = Char.code (Bytes.get buf (off + 1)) in
    Ok (b0 lor (b1 lsl 8))

let read_u32_le buf off =
  match check_bounds buf off 4 "read_u32_le" with
  | Error e -> Error e
  | Ok () ->
    let b0 = Char.code (Bytes.get buf  off)      in
    let b1 = Char.code (Bytes.get buf (off + 1)) in
    let b2 = Char.code (Bytes.get buf (off + 2)) in
    let b3 = Char.code (Bytes.get buf (off + 3)) in
    Ok (b0 lor (b1 lsl 8) lor (b2 lsl 16) lor (b3 lsl 24))

let read_u64_le buf off =
  match check_bounds buf off 8 "read_u64_le" with
  | Error e -> Error e
  | Ok () ->
    (* Build as two 32-bit halves to avoid OCaml int-width portability issues. *)
    let lo = Int32.of_int
      (Char.code (Bytes.get buf  off)
       lor (Char.code (Bytes.get buf (off + 1)) lsl 8)
       lor (Char.code (Bytes.get buf (off + 2)) lsl 16)
       lor (Char.code (Bytes.get buf (off + 3)) lsl 24)) in
    let hi = Int32.of_int
      (Char.code (Bytes.get buf (off + 4))
       lor (Char.code (Bytes.get buf (off + 5)) lsl 8)
       lor (Char.code (Bytes.get buf (off + 6)) lsl 16)
       lor (Char.code (Bytes.get buf (off + 7)) lsl 24)) in
    (* Combine as Int64: hi occupies bits 32..63, lo bits 0..31. *)
    let lo64 = Int64.logand (Int64.of_int32 lo) 0x0000_0000_FFFF_FFFFL in
    let hi64 = Int64.shift_left (Int64.of_int32 hi) 32 in
    Ok (Int64.logor hi64 lo64)

(* Big-endian: byte at [off] is the most-significant byte. *)
let read_u16_be buf off =
  match check_bounds buf off 2 "read_u16_be" with
  | Error e -> Error e
  | Ok () ->
    let b0 = Char.code (Bytes.get buf  off)      in   (* MSB *)
    let b1 = Char.code (Bytes.get buf (off + 1)) in
    Ok ((b0 lsl 8) lor b1)

let read_u32_be buf off =
  match check_bounds buf off 4 "read_u32_be" with
  | Error e -> Error e
  | Ok () ->
    let b0 = Char.code (Bytes.get buf  off)      in
    let b1 = Char.code (Bytes.get buf (off + 1)) in
    let b2 = Char.code (Bytes.get buf (off + 2)) in
    let b3 = Char.code (Bytes.get buf (off + 3)) in
    Ok ((b0 lsl 24) lor (b1 lsl 16) lor (b2 lsl 8) lor b3)

(* ------------------------------------------------------------------ writes *)

let write_u16_le v =
  if v < 0 || v > 0xFFFF then
    invalid_arg (Printf.sprintf "Bytes_util.write_u16_le: value %d out of range" v);
  let b = Bytes.create 2 in
  Bytes.set b 0 (Char.chr  (v         land 0xFF));
  Bytes.set b 1 (Char.chr ((v lsr  8) land 0xFF));
  b

let write_u32_le v =
  if v < 0 || v > 0xFFFF_FFFF then
    invalid_arg (Printf.sprintf "Bytes_util.write_u32_le: value %d out of range" v);
  let b = Bytes.create 4 in
  Bytes.set b 0 (Char.chr  (v          land 0xFF));
  Bytes.set b 1 (Char.chr ((v lsr  8)  land 0xFF));
  Bytes.set b 2 (Char.chr ((v lsr 16)  land 0xFF));
  Bytes.set b 3 (Char.chr ((v lsr 24)  land 0xFF));
  b

let write_u64_le v =
  let b = Bytes.create 8 in
  let set i shift =
    let byte = Int64.to_int (Int64.logand (Int64.shift_right_logical v shift) 0xFFL) in
    Bytes.set b i (Char.chr byte)
  in
  set 0 0;  set 1 8;  set 2 16; set 3 24;
  set 4 32; set 5 40; set 6 48; set 7 56;
  b

let write_u16_be v =
  if v < 0 || v > 0xFFFF then
    invalid_arg (Printf.sprintf "Bytes_util.write_u16_be: value %d out of range" v);
  let b = Bytes.create 2 in
  Bytes.set b 0 (Char.chr ((v lsr  8) land 0xFF));
  Bytes.set b 1 (Char.chr  (v         land 0xFF));
  b

let write_u32_be v =
  if v < 0 || v > 0xFFFF_FFFF then
    invalid_arg (Printf.sprintf "Bytes_util.write_u32_be: value %d out of range" v);
  let b = Bytes.create 4 in
  Bytes.set b 0 (Char.chr ((v lsr 24) land 0xFF));
  Bytes.set b 1 (Char.chr ((v lsr 16) land 0xFF));
  Bytes.set b 2 (Char.chr ((v lsr  8) land 0xFF));
  Bytes.set b 3 (Char.chr  (v         land 0xFF));
  b

(* ------------------------------------------------------------------ slice *)

let slice buf off len =
  match check_bounds buf off len "slice" with
  | Error e -> Error e
  | Ok () ->
    Ok (Bytes.sub buf off len)

let slice_string buf off len =
  Result.map Bytes.to_string (slice buf off len)

(* ------------------------------------------------------------------ misc *)

let concat parts =
  let total = List.fold_left (fun acc b -> acc + Bytes.length b) 0 parts in
  let buf = Bytes.create total in
  let _ = List.fold_left (fun pos b ->
    let n = Bytes.length b in
    Bytes.blit b 0 buf pos n;
    pos + n
  ) 0 parts in
  buf

let of_string s = Bytes.unsafe_of_string s
let to_string b = Bytes.unsafe_to_string b
let length b    = Bytes.length b
