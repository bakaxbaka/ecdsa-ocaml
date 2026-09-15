module Scalar : sig
  type t = private Z.t
  val modulus : Z.t
  val zero : t
  val one : t
  val of_z : Z.t -> t
  val to_z : t -> Z.t
  val add : t -> t -> t
  val sub : t -> t -> t
  val mul : t -> t -> t
  val neg : t -> t
  val inv : t -> (t, string) result
  val pow : t -> Z.t -> t
  val equal : t -> t -> bool
  val compare : t -> t -> int
  val is_zero : t -> bool
  val to_hex : t -> string
  val of_hex : string -> (t, string) result
end = 
  struct
    type t = Z.t

    let modulus =
      Z.of_string "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"

    let mod_n z =
      let r = Z.erem z modulus in
      if Z.sign r < 0 then Z.add r modulus else r

    let zero = mod_n Z.zero
    let one = mod_n Z.one

    let of_z z =
      mod_n z

    let to_z x =
      x

    let add x y =
      mod_n Z.(x + y)

    let sub x y =
      mod_n Z.(x - y)

    let mul x y =
      mod_n Z.(x * y)

    let neg x =
      if Z.equal x Z.zero then Z.zero
      else Z.sub modulus x

    let inv x =
      if Z.equal x Z.zero then
        Error "Cannot invert zero"
      else
        let i = Z.invert x modulus in
        if Z.equal i Z.zero then
          Error "Element is not invertible"
        else
          Ok (mod_n i)

    let pow x exponent =
      if Z.sign exponent < 0 then
        match inv x with
        | Error e -> failwith e
        | Ok x_inv ->
            Z.powm x_inv (Z.neg exponent) modulus
      else
        Z.powm x exponent modulus

    let equal x y =
      Z.equal x y

    let compare x y =
      Z.compare x y

    let is_zero x =
      Z.equal x Z.zero

    let to_hex x =
      Z.format "%x" x

    let of_hex s =
      try
        let s =
          if String.length s >= 2 &&
             String.sub s 0 2 = "0x"
          then
            String.sub s 2 (String.length s - 2)
          else
            s
        in
        if s = "" then
          Error "Empty hexadecimal string"
        else
          Ok (of_z (Z.of_string ("0x" ^ s)))
      with _ ->
        Error "Invalid hexadecimal string"
  end
