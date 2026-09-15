(** BIP143 (SegWit) Bitcoin SIGHASH computation.

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

    {1 Scope}

    This module handles SegWit (BIP141/BIP143) transactions with segwit=true.
    Legacy transactions use {!Legacy.compute} instead.
*)

(** 0x01: SIGHASH_ALL -- signs all inputs and all outputs. *)
val sighash_all          : int

(** 0x02: SIGHASH_NONE -- signs all inputs, no outputs. *)
val sighash_none         : int

(** 0x03: SIGHASH_SINGLE -- signs all inputs, only the matching output. *)
val sighash_single       : int

(** 0x80: ANYONECANPAY flag -- OR with base type to allow additional inputs. *)
val sighash_anyonecanpay : int

(** [compute tx input_index script_code value sighash_type] returns the 32-byte
    BIP143 sighash preimage hash for the SegWit input at [input_index].

    [script_code] is the scriptPubKey of the output being spent, serialized
    as it would appear in a CTxOut (varint length followed by bytes).

    [value] is the amount of the output being spent, in satoshis.

    Returns [Error `Index_out_of_bounds] if [input_index >= List.length tx.inputs].
    Returns [Error `Invalid_sighash_type] if the base type is not 1, 2, or 3.

    For SIGHASH_SINGLE with [input_index >= List.length tx.outputs], returns
    a hash of all zeros (per BIP143 spec). *)
val compute :
  Types.transaction ->
  int ->
  bytes ->
  Int64.t ->
  int ->
  (bytes, [`Index_out_of_bounds | `Invalid_sighash_type]) result
