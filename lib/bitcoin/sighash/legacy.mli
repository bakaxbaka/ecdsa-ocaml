(** Legacy (pre-SegWit) Bitcoin SIGHASH computation.

    Computes the 32-byte message hash that is signed for a given input of a
    legacy (non-SegWit) transaction, following the original Satoshi algorithm.

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

    This module handles only legacy (pre-SegWit) transactions.
    SegWit inputs use BIP143 (see the [Bip143] module).
*)

(** 0x01: SIGHASH_ALL -- signs all inputs and all outputs. *)
val sighash_all          : int

(** 0x02: SIGHASH_NONE -- signs all inputs, no outputs. *)
val sighash_none         : int

(** 0x03: SIGHASH_SINGLE -- signs all inputs, only the matching output. *)
val sighash_single       : int

(** 0x80: ANYONECANPAY flag -- OR with base type to allow additional inputs. *)
val sighash_anyonecanpay : int

(** [compute tx input_index script_code sighash_type] returns the 32-byte
    legacy SIGHASH preimage hash for the input at [input_index].

    [script_code] is the subscript for that input, normally the scriptPubKey
    of the output being spent (with any OP_CODESEPARATOR occurrences up to the
    last one removed, though that stripping is the caller's responsibility).

    Returns [Error `Index_out_of_bounds] if [input_index >= List.length tx.inputs].
    Returns [Error `Invalid_sighash_type] if the base type is not 1, 2, or 3.

    For SIGHASH_SINGLE with [input_index >= List.length tx.outputs], returns
    the SIGHASH_SINGLE bug value (0x01 followed by 31 zero bytes), matching
    Bitcoin Core behaviour. *)
val compute :
  Types.transaction ->
  int ->
  bytes ->
  int ->
  (bytes, [`Index_out_of_bounds | `Invalid_sighash_type]) result
