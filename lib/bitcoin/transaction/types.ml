(* lib/bitcoin/transaction/types.ml
   Bitcoin transaction domain types — no parsing, no serialisation. *)

(* ------------------------------------------------------------------ types *)

type txid = bytes

type outpoint = {
  txid : txid;
  vout : int;
}

type tx_input = {
  previous_output : outpoint;
  script_sig      : bytes;
  sequence        : int;
}

type tx_output = {
  value         : Int64.t;
  script_pubkey : bytes;
}

type transaction = {
  version   : int;
  inputs    : tx_input list;
  outputs   : tx_output list;
  witnesses : bytes list list;
  lock_time : int;
  segwit    : bool;
}

(* ------------------------------------------------------------------ helpers *)

let coinbase_txid : txid = Bytes.make 32 '\x00'

let is_coinbase (input : tx_input) : bool =
  Bytes.equal input.previous_output.txid coinbase_txid
  && input.previous_output.vout = 0xFFFF_FFFF

(* txid display order: bytes reversed from internal order, printed as hex. *)
let txid_to_display_hex (t : txid) : string =
  let n = Bytes.length t in
  let buf = Buffer.create (n * 2) in
  for i = n - 1 downto 0 do
    Buffer.add_string buf
      (Printf.sprintf "%02x" (Char.code (Bytes.get t i)))
  done;
  Buffer.contents buf

let txid_of_display_hex (s : string) : (txid, Common.Parse_error.t) result =
  let n = String.length s in
  if n <> 64 then
    Error (Common.Parse_error.Bad_length "txid: expected 64 hex chars")
  else begin
    (* Decode hex pairs, then reverse the bytes into internal order. *)
    let nibble c =
      match c with
      | '0'..'9' -> Char.code c - Char.code '0'
      | 'a'..'f' -> Char.code c - Char.code 'a' + 10
      | 'A'..'F' -> Char.code c - Char.code 'A' + 10
      | _ -> -1
    in
    let display = Bytes.create 32 in
    let rec decode i =
      if i = 32 then Ok ()
      else
        let hi = nibble s.[i * 2] in
        let lo = nibble s.[i * 2 + 1] in
        if hi < 0 || lo < 0 then
          Error (Common.Parse_error.Bad_hex
                   (Printf.sprintf "txid: invalid char at position %d" (i * 2)))
        else begin
          Bytes.set display i (Char.chr (hi lsl 4 lor lo));
          decode (i + 1)
        end
    in
    match decode 0 with
    | Error e -> Error e
    | Ok () ->
      (* Reverse to get internal order. *)
      let internal = Bytes.create 32 in
      for i = 0 to 31 do
        Bytes.set internal i (Bytes.get display (31 - i))
      done;
      Ok internal
  end

(* ------------------------------------------------------------------ equality *)

let equal_outpoint a b =
  Bytes.equal a.txid b.txid && a.vout = b.vout

let equal_tx_input a b =
  equal_outpoint a.previous_output b.previous_output
  && Bytes.equal a.script_sig b.script_sig
  && a.sequence = b.sequence

let equal_tx_output a b =
  Int64.equal a.value b.value
  && Bytes.equal a.script_pubkey b.script_pubkey

let equal_transaction a b =
  a.version = b.version
  && List.equal equal_tx_input  a.inputs  b.inputs
  && List.equal equal_tx_output a.outputs b.outputs
  && List.equal (List.equal Bytes.equal) a.witnesses b.witnesses
  && a.lock_time = b.lock_time
  && a.segwit = b.segwit
