type t =
  | Infinity
  | Point of { x : Field.t; y : Field.t }

val generator : t

val is_on_curve : t -> bool
val equal       : t -> t -> bool
val x           : t -> Field.t option
val y           : t -> Field.t option

val neg        : t -> t
val double     : t -> t
val add        : t -> t -> t
val scalar_mul : Scalar.t -> t -> t

val to_uncompressed : t -> string
val to_compressed   : t -> string

val of_uncompressed : string -> (t, Common.Parse_error.t) result
val of_compressed   : string -> (t, Common.Parse_error.t) result