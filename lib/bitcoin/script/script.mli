(** Bitcoin Script structural domain types.

    This module defines the {e representation} of parsed Bitcoin Script
    instructions.  It does not implement:
    - script execution or stack-machine evaluation
    - opcode semantic interpretation
    - address/template recognition (P2PKH, P2SH, P2WPKH, P2WSH, Taproot)
    - signature verification
    - hashing or SIGHASH

    Those belong in later layers that consume this representation.

    {1 Opcode byte conventions}

    Bitcoin Script opcodes occupy the range [0x00..0xFF].  The opcode byte is
    preserved verbatim in every constructor so callers can always reconstruct
    the original wire bytes without loss.

    Push-data opcodes:
    {v
      0x00               OP_0 / OP_FALSE  -- pushes empty byte vector
      0x01..0x4b         OP_DATA_N        -- direct push of N bytes
      0x4c  (76)         OP_PUSHDATA1     -- 1-byte length prefix, then data
      0x4d  (77)         OP_PUSHDATA2     -- 2-byte LE length prefix, then data
      0x4e  (78)         OP_PUSHDATA4     -- 4-byte LE length prefix, then data
      0x4f  (79)         OP_1NEGATE       -- pushes -1 (no following data)
      0x51..0x60 (81-96) OP_1..OP_16      -- pushes small integers 1-16
    v}

    All other opcodes (flow control, crypto, arithmetic, ...) are represented
    as bare {!Opcode} values carrying only the byte.
*)

(** A single Bitcoin Script instruction.

    - [Push_data { opcode; data }] -- a push instruction.
      [opcode] is the original wire byte (0x00..0x4e or 0x4f or 0x51..0x60).
      [data] is the byte sequence actually pushed onto the stack.
      For OP_0 / OP_1NEGATE / OP_1..OP_16 the pushed value is implied by
      the opcode; [data] is [Bytes.empty] for these.
    - [Opcode op] -- any non-push instruction.
      [op] is the original opcode byte (0x00..0xFF). *)
type instruction =
  | Push_data of {
      opcode : int;   (** Wire opcode byte, 0x00..0x60 for push instructions. *)
      data   : bytes; (** Bytes pushed; [Bytes.empty] for implicit-value opcodes. *)
    }
  | Opcode of int     (** Non-push opcode byte, 0x00..0xFF. *)

(** A parsed Bitcoin Script: an ordered sequence of instructions. *)
type t = instruction list

(** {1 Constants} *)

(** The empty script. *)
val empty : t

(** [op_0] = 0x00: OP_0 / OP_FALSE -- pushes empty byte vector. *)
val op_0          : int

(** [op_pushdata1] = 0x4c: OP_PUSHDATA1 -- 1-byte length prefix. *)
val op_pushdata1  : int

(** [op_pushdata2] = 0x4d: OP_PUSHDATA2 -- 2-byte LE length prefix. *)
val op_pushdata2  : int

(** [op_pushdata4] = 0x4e: OP_PUSHDATA4 -- 4-byte LE length prefix. *)
val op_pushdata4  : int

(** [op_1negate] = 0x4f: OP_1NEGATE -- pushes -1. *)
val op_1negate    : int

(** [op_reserved] = 0x50: OP_RESERVED. *)
val op_reserved   : int

(** [op_1] = 0x51: OP_1 / OP_TRUE -- pushes 1. *)
val op_1          : int

(** [op_16] = 0x60: OP_16 -- pushes 16. *)
val op_16         : int

(** [op_dup] = 0x76: OP_DUP. *)
val op_dup        : int

(** [op_equalverify] = 0x88: OP_EQUALVERIFY. *)
val op_equalverify : int

(** [op_hash160] = 0xa9: OP_HASH160. *)
val op_hash160    : int

(** [op_checksig] = 0xac: OP_CHECKSIG. *)
val op_checksig   : int

(** [op_checkmultisig] = 0xae: OP_CHECKMULTISIG. *)
val op_checkmultisig : int

(** [op_return] = 0x6a: OP_RETURN. *)
val op_return     : int

(** {1 Classification} *)

(** [is_push instr] is [true] when [instr] is a [Push_data] instruction. *)
val is_push : instruction -> bool

(** [is_direct_push opcode] is [true] when [opcode] is in [0x01..0x4b]
    (a direct N-byte push where N = opcode). *)
val is_direct_push : int -> bool

(** [direct_push_length opcode] returns the number of bytes pushed by a
    direct-push opcode ([0x01..0x4b]).
    Raises [Invalid_argument] if [opcode] is outside that range. *)
val direct_push_length : int -> int

(** {1 Accessors} *)

(** [opcode_of instr] returns the wire opcode byte regardless of constructor. *)
val opcode_of : instruction -> int

(** [data_of instr] returns the push data for [Push_data] instructions,
    or [Bytes.empty] for plain [Opcode] instructions. *)
val data_of : instruction -> bytes

(** {1 Equality} *)

(** [equal_instruction a b] is structural equality on instructions. *)
val equal_instruction : instruction -> instruction -> bool

(** [equal a b] is structural equality on scripts. *)
val equal : t -> t -> bool
