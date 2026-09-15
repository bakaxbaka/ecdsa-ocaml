(* lib/crypto/encoding/hex.ml
   Hexadecimal codec. No dependencies beyond the OCaml stdlib and Common.

   Design notes:
   - Output is always lowercase, no "0x" prefix.
   - Input decoding strips a leading "0x" / "0X" prefix before processing.
   - All error paths surface as [Common.Parse_error.t] so callers can route
     hex errors through the same result type as the rest of the parsing stack. *)

(* ------------------------------------------------------------------ encode *)

let byte_to_hex_lo b = "0123456789abcdef".[b land 0x0f]
let byte_to_hex_hi b = "0123456789abcdef".[b lsr  4]

let of_bytes (b : bytes) : string =
  let n = Bytes.length b in
  let buf = Bytes.create (n * 2) in
  for i = 0 to n - 1 do
    let v = Char.code (Bytes.get b i) in
    Bytes.set buf (i * 2)     (byte_to_hex_hi v);
    Bytes.set buf (i * 2 + 1) (byte_to_hex_lo v)
  done;
  Bytes.unsafe_to_string buf

let of_string (s : string) : string =
  of_bytes (Bytes.unsafe_of_string s)

let pp_bytes = of_bytes

(* ------------------------------------------------------------------ decode *)

(* Maps a single hex nibble character to its value, or -1 on invalid input. *)
let nibble_of_char = function
  | '0' -> 0  | '1' -> 1  | '2' -> 2  | '3' -> 3
  | '4' -> 4  | '5' -> 5  | '6' -> 6  | '7' -> 7
  | '8' -> 8  | '9' -> 9
  | 'a' | 'A' -> 10 | 'b' | 'B' -> 11
  | 'c' | 'C' -> 12 | 'd' | 'D' -> 13
  | 'e' | 'E' -> 14 | 'f' | 'F' -> 15
  | _ -> -1

(* Strip a leading "0x" or "0X" prefix if present. *)
let strip_prefix (s : string) : string =
  let n = String.length s in
  if n >= 2 && s.[0] = '0' && (s.[1] = 'x' || s.[1] = 'X')
  then String.sub s 2 (n - 2)
  else s

let to_bytes (h : string) : (bytes, Common.Parse_error.t) result =
  let h = strip_prefix h in
  let n = String.length h in
  if n mod 2 <> 0 then
    Error (Common.Parse_error.Bad_length "hex: odd number of nibbles")
  else begin
    let out = Bytes.create (n / 2) in
    let rec loop i =
      if i = n / 2 then Ok out
      else
        let hi = nibble_of_char h.[i * 2] in
        let lo = nibble_of_char h.[i * 2 + 1] in
        if hi < 0 || lo < 0 then
          Error (Common.Parse_error.Bad_hex
                   (Printf.sprintf "hex: invalid character at position %d" (i * 2)))
        else begin
          Bytes.set out i (Char.chr (hi lsl 4 lor lo));
          loop (i + 1)
        end
    in
    loop 0
  end

let to_string (h : string) : (string, Common.Parse_error.t) result =
  Result.map Bytes.unsafe_to_string (to_bytes h)
