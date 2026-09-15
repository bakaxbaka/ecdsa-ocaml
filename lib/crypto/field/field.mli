module T : sig
  type t = private Z.t
  
  val modulus : Z.t
  val zero    : t
  val one     : t
  
  val of_z    : Z.t -> t
  val to_z    : t -> Z.t
  
  val add     : t -> t -> t
  val sub     : t -> t -> t
  val mul     : t -> t -> t
  val neg     : t -> t
  val inv     : t -> (t, string) result
  val pow     : t -> Z.t -> t
  
  val equal   : t -> t -> bool
  val compare : t -> t -> int
  val is_zero : t -> bool
  
  val to_hex  : t -> string
  (** Parses a canonical, non-negative field representative.  Values outside
      [[0, modulus - 1]] are rejected rather than reduced modulo [modulus]. *)
  val of_hex  : string -> (t, string) result
end

include module type of T
