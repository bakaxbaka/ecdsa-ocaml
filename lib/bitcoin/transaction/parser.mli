(** Bitcoin transaction wire-format parser.

    Parses the Bitcoin P2P serialisation format into {!Types.transaction}
    values.  Both legacy and SegWit (BIP141 / BIP144) formats are supported.

    {1 Error handling}

    All errors are returned as [Common.Parse_error.t]:
    - [Truncated ctx]     — buffer ended before the field named by [ctx] was complete
    - [Trailing_data ctx] — bytes remain in the buffer after a complete transaction
    - [Bad_length ctx]    — a CompactSize count or output value is out of range
                            (zero inputs, zero outputs, negative value, etc.)
    - [Non_canonical ctx] — a CompactSize integer used a non-minimal encoding

    {1 CompactSize}

    CompactSize (Bitcoin's variable-length integer) is decoded here and is
    {b not} part of [Bytes_util]: it is a Bitcoin wire-format concept.

    Encoding rules (canonical):
    {v
      0x00 – 0xFC          →  1 byte  (value as-is)
      0xFD 0xNN 0xNN       →  3 bytes (uint16 LE; value must be ≥ 0xFD)
      0xFE 0xNN 0xNN 0xNN 0xNN  →  5 bytes (uint32 LE; value must be ≥ 0x1_0000)
      0xFF … 8 bytes       →  9 bytes (uint64 LE; value must be ≥ 0x1_0000_0000)
    v}

    A non-minimal encoding (e.g. 0xFD 0x00 0x3F) is rejected with
    [Non_canonical].  CompactSize values above [Sys.max_string_length] are
    rejected with [Bad_length] because they cannot index a byte buffer on this
    platform.
*)

(** [of_bytes buf] parses exactly one transaction from [buf].
    Returns [Error (Trailing_data _)] if any bytes remain after the transaction. *)
val of_bytes : bytes -> (Types.transaction, Common.Parse_error.t) result

(** [of_hex h] decodes [h] from hex then calls {!of_bytes}.
    Accepts an optional leading "0x" prefix. *)
val of_hex : string -> (Types.transaction, Common.Parse_error.t) result
