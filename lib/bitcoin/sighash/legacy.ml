(* lib/bitcoin/sighash/legacy.ml
   Legacy (pre-SegWit) Bitcoin SIGHASH computation.

   Reference: Bitcoin Core SignatureHash() in script/interpreter.cpp
   https://github.com/bitcoin/bitcoin/blob/master/src/script/interpreter.cpp

   Serialisation format for the preimage is identical to the legacy transaction
   wire format, except inputs carry the modified scriptSigs and the sighash
   type word is appended. *)

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

(* Serialise one input (with an explicit scriptSig). *)
let ser_input (inp : Types.tx_input) script_sig =
  Bytes_util.concat [
    inp.previous_output.txid;
    u32_le inp.previous_output.vout;
    script_field script_sig;
    u32_le inp.sequence;
  ]

(* Serialise one output. *)
let ser_output (out : Types.tx_output) =
  Bytes_util.concat [
    u64_le out.value;
    script_field out.script_pubkey;
  ]

(* ------------------------------------------------------------------ compute *)

let compute (tx : Types.transaction) input_index script_code sighash_type =
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

      (* ---- Step 1-3: build modified inputs -------------------------------- *)
      (* For ANYONECANPAY we only include the one input being signed.
         Otherwise we include all inputs, with empty scriptSig except for
         the signed input. *)
      let signed_input = List.nth tx.inputs input_index in

      (* Sequences for non-signed inputs are zeroed for NONE and SINGLE. *)
      let zeroed_sequence = 0x00000000 in

      let modified_inputs =
        if anyonecanpay then
          (* Only the signed input, with its script_code. *)
          [ ser_input { signed_input with
              previous_output = signed_input.previous_output }
              script_code ]
        else
          List.mapi (fun i inp ->
            let sscript = if i = input_index then script_code else Bytes.empty in
            let seq =
              if i <> input_index &&
                 (base_type = sighash_none || base_type = sighash_single)
              then zeroed_sequence
              else inp.sequence
            in
            ser_input { inp with sequence = seq } sscript
          ) tx.inputs
      in

      (* ---- Step 4-5: build modified outputs ------------------------------- *)
      (* SIGHASH_SINGLE special case: if input_index >= n_outputs, Bitcoin Core
         returns a hash of 1 || 31 zeros (the "SIGHASH_SINGLE bug"). *)
      if base_type = sighash_single && input_index >= n_outputs then begin
        (* The "SIGHASH_SINGLE bug" return value *)
        let bug_hash = Bytes.make 32 '\x00' in
        Bytes.set bug_hash 0 '\x01';
        Ok bug_hash
      end else begin

        let modified_outputs =
          match base_type with
          | 1 (* ALL *)    -> List.map ser_output tx.outputs
          | 2 (* NONE *)   -> []
          | 3 (* SINGLE *) ->
            (* Only keep output at input_index; pad preceding ones with
               -1 value (0xffffffffffffffff) and empty script. *)
            List.mapi (fun i out ->
              if i = input_index then ser_output out
              else ser_output {
                value = Int64.minus_one;
                script_pubkey = Bytes.empty;
              }
            ) (List.filteri (fun i _ -> i <= input_index) tx.outputs)
          | _ -> assert false
        in

        (* ---- Step 6: serialise ------------------------------------------ *)
        let parts = [
          (* version: int32 LE *)
          u32_le tx.version;
          (* inputs *)
          varint (List.length modified_inputs);
          Bytes_util.concat modified_inputs;
          (* outputs *)
          varint (List.length modified_outputs);
          Bytes_util.concat modified_outputs;
          (* lock_time *)
          u32_le tx.lock_time;
          (* sighash type: 4-byte LE *)
          u32_le sighash_type;
        ] in
        let preimage = Bytes_util.concat parts in

        (* ---- Step 7: hash256 -------------------------------------------- *)
        Ok (Hash.hash256 preimage)
      end
    end
