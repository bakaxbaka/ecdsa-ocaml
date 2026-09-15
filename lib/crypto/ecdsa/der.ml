(* lib/crypto/ecdsa/der.ml
   Strict Bitcoin DER signature parser.

   Rules enforced (matching Bitcoin Core's IsValidSignatureEncoding):
   1. Non-empty
   2. First byte is 0x30 (SEQUENCE)
   3. Declared SEQUENCE length = total bytes - 2 (tag + length) - 1 (sighash)
   4. r INTEGER tag = 0x02
   5. r length in 1..33
   6. r bytes: if high bit set, must have 0x00 prefix; no unnecessary 0x00 prefix
   7. Same rules for s
   8. Trailing sighash byte present
   9. r value != 0, s value != 0

   Range checks [1, n-1] are NOT done here — that belongs in the ECDSA verify layer. *)

type parsed = {
  r       : Z.t;
  s       : Z.t;
  sighash : int;
}

(* ------------------------------------------------------------------ helpers *)

let err e = Error e

(* Read one byte at position pos; returns the byte and next position. *)
let read_byte buf pos =
  if pos >= Bytes.length buf then None
  else Some (Char.code (Bytes.get buf pos), pos + 1)

(* Read n bytes starting at pos; returns Bytes.t and next position. *)
let read_bytes buf pos n =
  if pos + n > Bytes.length buf then None
  else Some (Bytes.sub buf pos n, pos + n)

(* Decode a big-endian byte sequence as a non-negative Z.t. *)
let z_of_bytes b =
  let n = Bytes.length b in
  let result = ref Z.zero in
  for i = 0 to n - 1 do
    result := Z.add (Z.shift_left !result 8)
                    (Z.of_int (Char.code (Bytes.get b i)))
  done;
  !result

(* ------------------------------------------------------------------ integer field parser *)

(* Parse one DER INTEGER field (r or s) starting at pos.
   Returns (z_value, next_pos) or an error. *)
let parse_integer buf pos =
  (* INTEGER tag *)
  match read_byte buf pos with
  | None          -> err Common.Der_error.Bad_length
  | Some (tag, pos) ->
    if tag <> 0x02 then err Common.Der_error.Not_an_integer
    else
      (* INTEGER length *)
      match read_byte buf pos with
      | None          -> err Common.Der_error.Bad_length
      | Some (len, pos) ->
        if len = 0 then err Common.Der_error.Bad_length
        else if len > 33 then err Common.Der_error.Bad_length
        else
          match read_bytes buf pos len with
          | None              -> err Common.Der_error.Bad_length
          | Some (ibytes, pos) ->
            let first = Char.code (Bytes.get ibytes 0) in
            (* Negative: high bit set on first byte without 0x00 prefix *)
            if first land 0x80 <> 0 then
              err Common.Der_error.Negative_integer
            (* Unnecessary leading zero: 0x00 followed by byte with high bit clear *)
            else if len >= 2
                 && first = 0x00
                 && Char.code (Bytes.get ibytes 1) land 0x80 = 0 then
              err Common.Der_error.Excessive_padding
            else
              (* Strip a single canonical leading 0x00 (present when high bit is set
                 on the actual value, to avoid negative interpretation) *)
              let value_bytes =
                if first = 0x00 && len > 1 then Bytes.sub ibytes 1 (len - 1)
                else ibytes
              in
              let v = z_of_bytes value_bytes in
              if Z.equal v Z.zero then
                (* r=0 or s=0 is invalid *)
                err Common.Der_error.Bad_length  (* reuse: zero value is structurally wrong *)
              else
                Ok (v, pos)

(* ------------------------------------------------------------------ main parser *)

let of_bytes buf =
  let n = Bytes.length buf in
  if n = 0 then err Common.Der_error.Empty
  else
    (* SEQUENCE tag *)
    match read_byte buf 0 with
    | None -> err Common.Der_error.Empty
    | Some (tag, pos) ->
      if tag <> 0x30 then err Common.Der_error.Not_a_sequence
      else
        (* SEQUENCE length: must equal n - 2 (tag+len) - 1 (sighash) *)
        match read_byte buf pos with
        | None -> err Common.Der_error.Bad_length
        | Some (seq_len, pos) ->
          (* seq_len should cover the remainder minus the sighash byte:
             total = 1 (0x30) + 1 (seq_len byte) + seq_len + 1 (sighash)
             so: seq_len = n - 3 *)
          if seq_len <> n - 3 then err Common.Der_error.Bad_length
          else
            (* Parse r *)
            match parse_integer buf pos with
            | Error e -> Error e
            | Ok (r, pos) ->
              (* Parse s *)
              match parse_integer buf pos with
              | Error e -> Error e
              | Ok (s, pos) ->
                (* pos must now point at exactly the sighash byte *)
                if pos <> n - 1 then err Common.Der_error.Trailing_bytes
                else
                  match read_byte buf pos with
                  | None -> err Common.Der_error.Missing_sighash_byte
                  | Some (sighash, _) ->
                    Ok { r; s; sighash }

(* ------------------------------------------------------------------ hex entry point *)

let of_hex h =
  (* Manual hex decode to avoid a dependency on the encoding library.
     DER is in the crypto layer which sits below encoding in the dependency graph.
     We only need to handle even-length lowercase/uppercase hex. *)
  let h =
    if String.length h >= 2 && h.[0] = '0' && (h.[1] = 'x' || h.[1] = 'X')
    then String.sub h 2 (String.length h - 2)
    else h
  in
  let n = String.length h in
  if n mod 2 <> 0 then
    Error Common.Der_error.Bad_length
  else begin
    let buf = Bytes.create (n / 2) in
    let nibble c =
      match c with
      | '0'..'9' -> Char.code c - Char.code '0'
      | 'a'..'f' -> Char.code c - Char.code 'a' + 10
      | 'A'..'F' -> Char.code c - Char.code 'A' + 10
      | _        -> -1
    in
    let rec fill i =
      if i = n / 2 then Ok ()
      else
        let hi = nibble h.[i * 2] in
        let lo = nibble h.[i * 2 + 1] in
        if hi < 0 || lo < 0 then Error Common.Der_error.Bad_length
        else begin
          Bytes.set buf i (Char.chr (hi lsl 4 lor lo));
          fill (i + 1)
        end
    in
    match fill 0 with
    | Error e -> Error e
    | Ok ()   -> of_bytes buf
  end
