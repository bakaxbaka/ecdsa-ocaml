(** Generic byte-buffer utilities: fixed-width reads and writes
    in little-endian and big-endian byte order, bounds-checked access,
    and common slice/concatenation helpers.

    No Bitcoin-specific concepts (VarInt, CompactSize, scripts, etc.) belong here.
    Those live in the bitcoin/ serialization layer. *)

(** {1 Bounds-checked reads} *)

(** [read_byte buf off] reads one byte from [buf] at [off].
    Returns [Error] if [off] is out of range. *)
val read_byte : bytes -> int -> (int, Common.Parse_error.t) result

(** {1 Little-endian reads} *)

(** [read_u16_le buf off] reads a 2-byte little-endian unsigned integer. *)
val read_u16_le : bytes -> int -> (int, Common.Parse_error.t) result

(** [read_u32_le buf off] reads a 4-byte little-endian unsigned integer.
    The result fits in a 63-bit OCaml [int] on all supported platforms. *)
val read_u32_le : bytes -> int -> (int, Common.Parse_error.t) result

(** [read_u64_le buf off] reads an 8-byte little-endian unsigned integer
    as an [Int64]. Use [Int64.to_int] with caution — values above [max_int]
    will wrap on 32-bit platforms. *)
val read_u64_le : bytes -> int -> (Int64.t, Common.Parse_error.t) result

(** {1 Big-endian reads} *)

(** [read_u16_be buf off] reads a 2-byte big-endian unsigned integer. *)
val read_u16_be : bytes -> int -> (int, Common.Parse_error.t) result

(** [read_u32_be buf off] reads a 4-byte big-endian unsigned integer. *)
val read_u32_be : bytes -> int -> (int, Common.Parse_error.t) result

(** {1 Little-endian writes} *)

(** [write_u16_le v] serialises [v] as 2 bytes, little-endian.
    [v] must be in [[0, 0xFFFF]]; raises [Invalid_argument] otherwise. *)
val write_u16_le : int -> bytes

(** [write_u32_le v] serialises [v] as 4 bytes, little-endian.
    [v] must be in [[0, 0xFFFF_FFFF]]. *)
val write_u32_le : int -> bytes

(** [write_u64_le v] serialises [v] as 8 bytes, little-endian. *)
val write_u64_le : Int64.t -> bytes

(** {1 Big-endian writes} *)

(** [write_u16_be v] serialises [v] as 2 bytes, big-endian. *)
val write_u16_be : int -> bytes

(** [write_u32_be v] serialises [v] as 4 bytes, big-endian. *)
val write_u32_be : int -> bytes

(** {1 Slice / copy helpers} *)

(** [slice buf off len] returns a fresh [bytes] copy of [buf[off .. off+len-1]].
    Returns [Error] if the range falls outside [buf]. *)
val slice : bytes -> int -> int -> (bytes, Common.Parse_error.t) result

(** [slice_string buf off len] is [slice] with result mapped to [string]. *)
val slice_string : bytes -> int -> int -> (string, Common.Parse_error.t) result

(** [concat parts] concatenates a list of [bytes] values into one buffer. *)
val concat : bytes list -> bytes

(** {1 Conversion helpers} *)

(** [of_string s] wraps a [string] as [bytes] without copying. *)
val of_string : string -> bytes

(** [to_string b] wraps [b] as a [string] without copying. *)
val to_string : bytes -> string

(** [length b] is [Bytes.length b]. *)
val length : bytes -> int
