(* lib/bitcoin/sighash/bip143.ml
   BIP143 (SegWit) Bitcoin SIGHASH computation.

   Reference: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki

   For SegWit v0 inputs, the sighash is computed from a serialized transaction
   that includes:
     1. nVersion (4-byte LE)
     2. hashPrevouts (32-byte double-SHA256 of serialized prevouts)
     3. hashSequence (32-byte double-SHA256 of serialized sequences)
     4. outpoint (32-byte txid + 4-byte vout LE)
     5. scriptCode (serialized scriptPubKey)
     6. value of the output spent by this input (8-byte LE)
     7. nSequence (4-byte LE)
     8. hashOutputs (32-byte double-SHA256 of serialized outputs)
     9. nLocktime (4-byte LE)
    10. sighash type (4-byte LE)

   The hashPrevouts/hashSequence/hashOutputs are pre-hashed to avoid O(n2)
   hashing and to include the input amount in the signature.

   {1 SIGHASH types}

   The sighash type is a 4-byte LE integer appended to the serialised
   transaction before hashing.  The low byte selects the base type;
   bit 7 (0x80) is the ANYONECANPAY flag.

   {v
     0x01  SIGHASH_ALL          -- signs all inputs and all outputs
     0x02  SIGHASH_NONE         -- signs all inputs, no outputs
     0x03  SIGHASH_SINGLE       -- signs all inputs, only the output at
                                   the same index as the signed input
     0x81  SIGHASH_ALL    | ANYONECANPAY
     0x82  SIGHASH_NONE   | ANYONECANPAY
     0x83  SIGHASH_SINGLE | ANYONECANPAY
   v}
*)

(* Bring record field names into scope unambiguously. *)
open Types

(* ------------------------------------------------------------------ constants *)

let sighash_all          = 0x01
let sighash_none         = 0x02
let sighash_single       = 0x03
let sighash_anyonecanpay = 0x80

(* ------------------------------------------------------------------ serialisation helpers *)

(* CompactSize (VarInt) encoding — Bitcoin wire format. *)
let varint n =
  if n <= 0xfc then
    let b = Bytes.create 1 in
    Bytes.set b 0 (Char.chr n); b
  else if n <= 0xffff then
    let b = Bytes.create 3 in
    Bytes.set b 0 '\xfd';
    Bytes.set b 1 (Char.chr  (n         land 0xff));
    Bytes.set b 2 (Char.chr ((n lsr  8) land 0xff));
    b
  else if n <= 0xffff_ffff then
    let b = Bytes.create 5 in
    Bytes.set b 0 '\xfe';
    Bytes.set b 1 (Char.chr  (n          land 0xff));
    Bytes.set b 2 (Char.chr ((n lsr  8)  land 0xff));
    Bytes.set b 3 (Char.chr ((n lsr 16)  land 0xff));
    Bytes.set b 4 (Char.chr ((n lsr 24)  land 0xff));
    b
  else failwith "varint: value too large"

let u32_le v =
  Bytes_util.write_u32_le v

let u64_le v =
  Bytes_util.write_u64_le v

(* Serialise bytes field: varint(length) || bytes *)
let script_field s =
  Bytes_util.concat [varint (Bytes.length s); s]

(* Serialise one outpoint (txid + vout). *)
let ser_outpoint (out : outpoint) =
  Bytes_util.concat [
    out.txid;
    u32_le out.vout;
  ]

(* Serialise one input's prevout (for hashPrevouts). *)
let ser_prevout (inp : tx_input) =
  ser_outpoint inp.previous_output

(* Serialise one input's sequence (for hashSequence). *)
let ser_sequence (inp : tx_input) =
  u32_le inp.sequence

(* Serialise one output. *)
let ser_output (out : tx_output) =
  Bytes_util.concat [
    u64_le out.value;
    script_field out.script_pubkey;
  ]

(* ------------------------------------------------------------------ compute *)

let compute (tx : transaction) input_index script_code value sighash_type =
  let n_inputs  = List.length tx.inputs  in
  let n_outputs = List.length tx.outputs in

  if input_index < 0 || input_index >= n_inputs then
    Error `Index_out_of_bounds
  else
    let base_type     = sighash_type land 0x1f in
    let anyonecanpay  = sighash_type land sighash_anyonecanpay <> 0 in

    if base_type < 1 || base_type > 3 then
      Error `Invalid_sighash_type
    else begin
      let signed_input = List.nth tx.inputs input_index in

      (* ---- Step 2: hashPrevouts ----------------------------------------- *)
      let hash_prevouts =
        if anyonecanpay then
          (* BIP143: hashPrevouts is 32 zero bytes when ANYONECANPAY is set *)
          Bytes.make 32 '\x00'
        else
          let prevouts = List.map ser_prevout tx.inputs in
          Hash.hash256 (Bytes_util.concat prevouts)
      in

      (* ---- Step 3: hashSequence ----------------------------------------- *)
      let hash_sequence =
        if anyonecanpay || base_type = sighash_none || base_type = sighash_single then
          (* BIP143: hashSequence is 32 zero bytes when ANYONECANPAY is set
             or when the base type is SIGHASH_NONE or SIGHASH_SINGLE *)
          Bytes.make 32 '\x00'
        else
          let sequences = List.map ser_sequence tx.inputs in
          Hash.hash256 (Bytes_util.concat sequences)
      in

      (* ---- Step 4: outpoint --------------------------------------------- *)
      let outpoint = ser_outpoint signed_input.previous_output in

      (* ---- Step 5: scriptCode ------------------------------------------- *)
      let script_code_serialized = script_field script_code in

      (* ---- Step 6: value ------------------------------------------------ *)
      let value_le = u64_le value in

      (* ---- Step 7: nSequence -------------------------------------------- *)
      let sequence =
        if anyonecanpay then
          signed_input.sequence
        else
          (* For non-ANYONECANPAY, all sequences are included as-is *)
          signed_input.sequence
      in
      let sequence_le = u32_le sequence in

      (* ---- Step 8: hashOutputs ------------------------------------------ *)
      let hash_outputs =
        match base_type with
        | 1 (* ALL *)    ->
          let outputs = List.map ser_output tx.outputs in
          Hash.hash256 (Bytes_util.concat outputs)
        | 2 (* NONE *)   ->
          Bytes.make 32 '\x00'  (* All zero hash *)
        | 3 (* SINGLE *) ->
          (* SIGHASH_SINGLE with SegWit: only hash output at input_index *)
          if input_index >= n_outputs then
            (* For SINGLE, if input_index >= n_outputs, the spec says
               hashOutputs should be all zeros. This differs from legacy
               which returns a special "bug" hash. *)
            Bytes.make 32 '\x00'
          else
            let outputs = [ ser_output (List.nth tx.outputs input_index) ] in
            Hash.hash256 (Bytes_util.concat outputs)
        | _ -> assert false
      in

      (* ---- Step 9: nLocktime -------------------------------------------- *)
      let locktime_le = u32_le tx.lock_time in

      (* ---- Step 10: sighash type ---------------------------------------- *)
      let sighash_le = u32_le sighash_type in

      (* ---- Final: concatenate and hash256 ------------------------------- *)
      let preimage = Bytes_util.concat [
        u32_le tx.version;
        hash_prevouts;
        hash_sequence;
        outpoint;
        script_code_serialized;
        value_le;
        sequence_le;
        hash_outputs;
        locktime_le;
        sighash_le;
      ] in

      Ok (Hash.hash256 preimage)
    end
