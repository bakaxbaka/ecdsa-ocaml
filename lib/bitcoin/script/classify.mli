(** Bitcoin scriptPubKey type classifier.

    Recognises standard output script patterns from raw scriptPubKey bytes.
    Does not execute scripts — purely structural byte-pattern matching.

    {1 Supported types}

    {v
      P2PKH    OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
      P2PK     <33|65 bytes pubkey> OP_CHECKSIG
      P2SH     OP_HASH160 <20 bytes> OP_EQUAL
      P2WPKH   OP_0 <20 bytes>   (witness v0, 22-byte script)
      P2WSH    OP_0 <32 bytes>   (witness v0, 34-byte script)
      P2TR     OP_1 <32 bytes>   (witness v1, taproot)
      OP_RETURN first byte 0x6a
      Unknown  anything else
    v}
*)

(** Standard Bitcoin output script types. *)
type script_type =
  | P2PKH
  | P2PK
  | P2SH
  | P2WPKH
  | P2WSH
  | P2TR
  | OP_RETURN
  | Unknown

(** [to_string t] returns the human-readable name of [t]. *)
val to_string : script_type -> string

(** [of_script_pubkey spk] classifies [spk] by byte-pattern matching. *)
val of_script_pubkey : bytes -> script_type

(** [script_code_for_p2wpkh spk] constructs the BIP143 script_code from a
    P2WPKH scriptPubKey (converts the 20-byte witness program into the
    equivalent P2PKH script: OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG).
    Returns [None] if [spk] is not a valid P2WPKH script. *)
val script_code_for_p2wpkh : bytes -> bytes option

(** [hash160_of_p2pkh spk] extracts the 20-byte hash160 from a P2PKH script.
    Returns [None] if not P2PKH. *)
val hash160_of_p2pkh : bytes -> bytes option

(** [hash160_of_p2wpkh spk] extracts the 20-byte witness program from P2WPKH.
    Returns [None] if not P2WPKH. *)
val hash160_of_p2wpkh : bytes -> bytes option

(** [pubkey_of_p2pk spk] extracts the raw public key from a P2PK script.
    Returns [None] if not P2PK. *)
val pubkey_of_p2pk : bytes -> bytes option
