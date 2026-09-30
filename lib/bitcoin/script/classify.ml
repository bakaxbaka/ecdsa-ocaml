(* lib/bitcoin/script/classify.ml
   Bitcoin scriptPubKey type classification.

   Recognises standard output script patterns by inspecting raw bytes.
   No script execution — purely structural pattern matching on byte sequences.

   Patterns recognised (by scriptPubKey byte content):

     P2PKH   : OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
                0x76 0xa9 0x14 <20 bytes> 0x88 0xac   (25 bytes)

     P2PK    : <33|65 bytes pubkey> OP_CHECKSIG
                0x21|0x41 <pubkey bytes> 0xac           (35 or 67 bytes)

     P2SH    : OP_HASH160 <20 bytes> OP_EQUAL
                0xa9 0x14 <20 bytes> 0x87               (23 bytes)

     P2WPKH  : OP_0 <20 bytes>  (witness version 0, 20-byte program)
                0x00 0x14 <20 bytes>                    (22 bytes)

     P2WSH   : OP_0 <32 bytes>  (witness version 0, 32-byte program)
                0x00 0x20 <32 bytes>                    (34 bytes)

     P2TR    : OP_1 <32 bytes>  (witness version 1, taproot)
                0x51 0x20 <32 bytes>                    (34 bytes)

     OP_RETURN: unspendable data carrier
                0x6a ...

     Unknown : anything else
*)

(* ------------------------------------------------------------------ types *)

type script_type =
  | P2PKH                   (* Pay-to-Public-Key-Hash  *)
  | P2PK                    (* Pay-to-Public-Key       *)
  | P2SH                    (* Pay-to-Script-Hash      *)
  | P2WPKH                  (* Pay-to-Witness-PubKey-Hash (native SegWit v0) *)
  | P2WSH                   (* Pay-to-Witness-Script-Hash (native SegWit v0) *)
  | P2TR                    (* Pay-to-Taproot           (native SegWit v1) *)
  | OP_RETURN               (* Unspendable data carrier *)
  | Unknown                 (* Anything else            *)

let to_string = function
  | P2PKH    -> "P2PKH"
  | P2PK     -> "P2PK"
  | P2SH     -> "P2SH"
  | P2WPKH   -> "P2WPKH"
  | P2WSH    -> "P2WSH"
  | P2TR     -> "P2TR"
  | OP_RETURN-> "OP_RETURN"
  | Unknown  -> "Unknown"

(* ------------------------------------------------------------------ helpers *)

let get b i = Char.code (Bytes.get b i)

(* ------------------------------------------------------------------ classifier *)

(** [of_script_pubkey spk] classifies the scriptPubKey bytes [spk]. *)
let of_script_pubkey (spk : bytes) : script_type =
  let n = Bytes.length spk in
  match n with
  (* P2WPKH: 0x00 0x14 <20 bytes> = 22 bytes *)
  | 22 when get spk 0 = 0x00 && get spk 1 = 0x14 -> P2WPKH

  (* P2SH:   0xa9 0x14 <20 bytes> 0x87 = 23 bytes *)
  | 23 when get spk 0 = 0xa9
         && get spk 1 = 0x14
         && get spk 22 = 0x87 -> P2SH

  (* P2PKH:  0x76 0xa9 0x14 <20 bytes> 0x88 0xac = 25 bytes *)
  | 25 when get spk 0 = 0x76
         && get spk 1 = 0xa9
         && get spk 2 = 0x14
         && get spk 23 = 0x88
         && get spk 24 = 0xac -> P2PKH

  (* P2WSH:  0x00 0x20 <32 bytes> = 34 bytes *)
  | 34 when get spk 0 = 0x00 && get spk 1 = 0x20 -> P2WSH

  (* P2TR:   0x51 0x20 <32 bytes> = 34 bytes *)
  | 34 when get spk 0 = 0x51 && get spk 1 = 0x20 -> P2TR

  (* P2PK compressed: 0x21 <33 bytes> 0xac = 35 bytes *)
  | 35 when get spk 0 = 0x21
         && get spk 34 = 0xac -> P2PK

  (* P2PK uncompressed: 0x41 <65 bytes> 0xac = 67 bytes *)
  | 67 when get spk 0 = 0x41
         && get spk 66 = 0xac -> P2PK

  (* OP_RETURN: first byte 0x6a *)
  | _ when n >= 1 && get spk 0 = 0x6a -> OP_RETURN

  | _ -> Unknown

(* ------------------------------------------------------------------ script_code helpers *)

(** [script_code_for_p2wpkh spk] derives the BIP143 script_code from a
    P2WPKH scriptPubKey.
    P2WPKH scriptPubKey: 0x00 0x14 <hash160>
    BIP143 script_code : 0x76 0xa9 0x14 <hash160> 0x88 0xac  (P2PKH form)
    Returns [None] if [spk] is not a valid P2WPKH script. *)
let script_code_for_p2wpkh (spk : bytes) : bytes option =
  if Bytes.length spk = 22
     && get spk 0 = 0x00
     && get spk 1 = 0x14
  then begin
    let hash160 = Bytes.sub spk 2 20 in
    let sc = Bytes.create 25 in
    Bytes.set sc 0  '\x76';   (* OP_DUP       *)
    Bytes.set sc 1  '\xa9';   (* OP_HASH160   *)
    Bytes.set sc 2  '\x14';   (* push 20 bytes*)
    Bytes.blit hash160 0 sc 3 20;
    Bytes.set sc 23 '\x88';   (* OP_EQUALVERIFY *)
    Bytes.set sc 24 '\xac';   (* OP_CHECKSIG    *)
    Some sc
  end else
    None

(** [hash160_of_p2pkh spk] extracts the 20-byte hash160 from a P2PKH script.
    Returns [None] if [spk] is not a valid P2PKH script. *)
let hash160_of_p2pkh (spk : bytes) : bytes option =
  if Bytes.length spk = 25
     && get spk 0 = 0x76
     && get spk 1 = 0xa9
     && get spk 2 = 0x14
     && get spk 23 = 0x88
     && get spk 24 = 0xac
  then Some (Bytes.sub spk 3 20)
  else None

(** [hash160_of_p2wpkh spk] extracts the 20-byte witness program from P2WPKH. *)
let hash160_of_p2wpkh (spk : bytes) : bytes option =
  if Bytes.length spk = 22
     && get spk 0 = 0x00
     && get spk 1 = 0x14
  then Some (Bytes.sub spk 2 20)
  else None

(** [pubkey_of_p2pk spk] extracts the raw public key bytes from a P2PK script.
    Returns [None] if [spk] is not P2PK. *)
let pubkey_of_p2pk (spk : bytes) : bytes option =
  let n = Bytes.length spk in
  if (n = 35 && get spk 0 = 0x21 && get spk 34 = 0xac)
  then Some (Bytes.sub spk 1 33)
  else if (n = 67 && get spk 0 = 0x41 && get spk 66 = 0xac)
  then Some (Bytes.sub spk 1 65)
  else None
