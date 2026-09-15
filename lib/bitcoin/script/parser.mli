(** Bitcoin Script wire-format parser.

    Decodes raw script bytes into a {!Script.t} (list of {!Script.instruction}).

    {1 Parsing rules}

    Each instruction begins with one opcode byte:

    {v
      0x00               OP_0        -- Push_data { opcode=0x00; data=empty }
      0x01..0x4b         OP_DATA_N   -- Push_data { opcode=N; data = next N bytes }
      0x4c               OP_PUSHDATA1 -- 1-byte LE length L, then L bytes
      0x4d               OP_PUSHDATA2 -- 2-byte LE length L, then L bytes
      0x4e               OP_PUSHDATA4 -- 4-byte LE length L, then L bytes
      0x4f               OP_1NEGATE   -- Push_data { opcode=0x4f; data=empty }
      0x51..0x60         OP_1..OP_16  -- Push_data { opcode; data=empty }
      anything else      Opcode byte  -- Opcode op
    v}

    Parsing consumes {e all} bytes; leftover bytes are not an error
    (scripts are length-delimited by their container — the transaction parser
    already extracted the exact byte range).

    {1 Error handling}

    - [Truncated ctx]   -- buffer ended before a push-data field was complete
    - [Bad_length ctx]  -- a PUSHDATA length field exceeds the remaining buffer
                          or exceeds [Sys.max_string_length]
*)

(** [of_bytes buf] parses all bytes in [buf] as a Bitcoin Script.
    Returns the list of instructions in order. *)
val of_bytes : bytes -> (Script.t, Common.Parse_error.t) result

(** [of_hex h] decodes [h] from hex (accepting an optional "0x" prefix)
    then calls {!of_bytes}. *)
val of_hex : string -> (Script.t, Common.Parse_error.t) result
