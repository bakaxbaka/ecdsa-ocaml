(* lib/bitcoin/script/types.ml
   Bitcoin Script structural domain types.

   No execution semantics, no opcode interpretation, no hashing.
   The opcode byte is preserved verbatim in every instruction so the
   original wire bytes can always be recovered without loss. *)

(* ------------------------------------------------------------------ types *)

type instruction =
  | Push_data of {
      opcode : int;
      data   : bytes;
    }
  | Opcode of int

type t = instruction list

(* ------------------------------------------------------------------ constants *)

let empty : t = []

(* Push-data opcodes *)
let op_0         = 0x00
let op_pushdata1 = 0x4c
let op_pushdata2 = 0x4d
let op_pushdata4 = 0x4e
let op_1negate   = 0x4f
let op_reserved  = 0x50
let op_1         = 0x51
let op_16        = 0x60

(* Frequently referenced non-push opcodes *)
let op_dup           = 0x76
let op_equalverify   = 0x88
let op_hash160       = 0xa9
let op_checksig      = 0xac
let op_checkmultisig = 0xae
let op_return        = 0x6a

(* ------------------------------------------------------------------ classification *)

let is_push = function
  | Push_data _ -> true
  | Opcode _    -> false

(* Direct push: opcode 0x01..0x4b means "push exactly opcode bytes". *)
let is_direct_push opcode = opcode >= 0x01 && opcode <= 0x4b

let direct_push_length opcode =
  if not (is_direct_push opcode) then
    invalid_arg
      (Printf.sprintf "Script.Types.direct_push_length: opcode 0x%02x is not a direct push" opcode)
  else
    opcode

(* ------------------------------------------------------------------ accessors *)

let opcode_of = function
  | Push_data { opcode; _ } -> opcode
  | Opcode op               -> op

let data_of = function
  | Push_data { data; _ } -> data
  | Opcode _              -> Bytes.empty

(* ------------------------------------------------------------------ equality *)

let equal_instruction a b =
  match a, b with
  | Push_data p, Push_data q ->
    p.opcode = q.opcode && Bytes.equal p.data q.data
  | Opcode x, Opcode y -> x = y
  | _ -> false

let equal a b = List.equal equal_instruction a b
