(** Bitcoin transaction domain types.

    These are pure data types representing the decoded structure of a Bitcoin
    transaction.  No parsing logic, no serialisation logic, no cryptography.
    Those belong in separate modules that consume these types.

    Field widths and byte-order conventions follow the Bitcoin P2P serialisation
    format (little-endian unless noted):

    {v
    Transaction
      version     : int32   (LE, signed, but practically 1 or 2)
      inputs      : TxInput list
      outputs     : TxOutput list
      lock_time   : uint32  (LE)
      segwit_flag : bool    (true when marker=0x00 + flag=0x01 present)
    v}
*)

(** A transaction identifier: 32 bytes in internal byte order
    (reversed from the display/RPC hex order).

    Stored as [bytes] rather than a [string] to make the binary nature
    explicit and avoid accidental UTF-8 interpretation. *)
type txid = bytes

(** An unambiguous reference to a specific output of a previous transaction.

    {v
    Wire layout (36 bytes):
      txid  : 32 bytes  (transaction hash, internal byte order)
      vout  :  4 bytes  (output index, uint32 LE)
    v} *)
type outpoint = {
  txid : txid;
  (** 32-byte transaction hash in {e internal} byte order. *)
  vout : int;
  (** Output index.  Wire type is uint32; represented as [int] because
      no valid transaction has 2^30+ outputs, so the value always fits. *)
}

(** A transaction input.

    {v
    Wire layout:
      previous_output : 36 bytes   (outpoint)
      script_sig      : varint len + bytes
      sequence        : 4 bytes    (uint32 LE)
    v} *)
type tx_input = {
  previous_output : outpoint;
  script_sig      : bytes;
  (** Raw scriptSig bytes.  Parsing the script language is the
      responsibility of the script layer, not the transaction type layer. *)
  sequence        : int;
  (** Sequence number.  Wire type is uint32; [int] is sufficient on all
      64-bit platforms (max value 0xFFFF_FFFF fits in 63-bit OCaml [int]). *)
}

(** A transaction output.

    {v
    Wire layout:
      value         : 8 bytes   (int64 LE, satoshis)
      script_pubkey : varint len + bytes
    v} *)
type tx_output = {
  value         : Int64.t;
  (** Output value in satoshis.  Bitcoin's maximum possible value
      (20_999_999.97690000 BTC = 2_099_999_997_690_000 sat) fits
      well within [Int64.max_int] (9_223_372_036_854_775_807).
      Negative values are invalid and must be rejected by the parser.
      [Int64.t] is used rather than [int] to be explicit about the
      8-byte wire width and to remain correct on 32-bit hosts. *)
  script_pubkey : bytes;
  (** Raw scriptPubKey bytes. *)
}

(** A complete Bitcoin transaction.

    Supports both legacy (pre-SegWit) and SegWit (BIP141) transactions.
    The [witnesses] field is non-empty exactly when [segwit] is [true];
    each element corresponds to the input at the same index.

    {v
    Legacy wire layout:
      version   :  4 bytes  (int32 LE)
      vin count :  varint
      inputs    :  vin_count × TxInput
      vout count:  varint
      outputs   :  vout_count × TxOutput
      lock_time :  4 bytes  (uint32 LE)

    SegWit wire layout (BIP144):
      version   :  4 bytes  (int32 LE)
      marker    :  1 byte   (0x00)
      flag      :  1 byte   (≥ 0x01, currently always 0x01)
      vin count :  varint
      inputs    :  vin_count × TxInput
      vout count:  varint
      outputs   :  vout_count × TxOutput
      witnesses :  vin_count × (varint item_count × (varint len + bytes))
      lock_time :  4 bytes  (uint32 LE)
    v} *)
type transaction = {
  version   : int;
  (** Transaction version.  Wire type is int32 LE.  Version 1 and 2 are
      the only values seen in practice; represented as [int]. *)
  inputs    : tx_input list;
  outputs   : tx_output list;
  witnesses : bytes list list;
  (** Per-input witness stacks.  Empty list for legacy transactions.
      For SegWit transactions, [List.length witnesses = List.length inputs]. *)
  lock_time : int;
  (** Lock time.  Wire type is uint32 LE; fits in 63-bit [int]. *)
  segwit    : bool;
  (** [true] when the transaction was parsed from the SegWit wire format
      (marker byte 0x00 + flag byte present). *)
}

(** The coinbase outpoint txid: 32 zero bytes. *)
val coinbase_txid : txid

(** [is_coinbase input] is [true] when [input] is a coinbase input:
    txid is all zeros and vout is [0xFFFF_FFFF]. *)
val is_coinbase : tx_input -> bool

(** Pretty-print a [txid] as a 64-character lowercase hex string
    in {e display} byte order (bytes reversed from internal order). *)
val txid_to_display_hex : txid -> string

(** [txid_of_display_hex s] parses a 64-character hex string in display
    order into a [txid] in internal byte order.
    Returns [Error] if [s] is not exactly 64 valid hex characters. *)
val txid_of_display_hex : string -> (txid, Common.Parse_error.t) result

(** [equal_outpoint a b] structural equality for outpoints. *)
val equal_outpoint : outpoint -> outpoint -> bool

(** [equal_transaction a b] structural equality for transactions. *)
val equal_transaction : transaction -> transaction -> bool
