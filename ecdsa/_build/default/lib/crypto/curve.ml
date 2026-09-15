open Field
open Scalar

module Curve : sig
  type point = Infinity | Point of Field.t * Field.t

  val generator       : point
  val is_on_curve     : point -> bool
  val neg             : point -> point
  val add             : point -> point -> point
  val double          : point -> point
  val scalar_mul      : Scalar.t -> point -> point
  val equal           : point -> point -> bool
  val x               : point -> Field.t option
  val y               : point -> Field.t option

  (* SEC 1 §2.3.3 / §2.3.4 serialization *)
  val to_uncompressed : point -> string            (* 04||X||Y   (130 hex) *)
  val to_compressed   : point -> string            (* 02/03||X    (66 hex) *)
  val of_uncompressed : string -> (point, string) result
  val of_compressed   : string -> (point, string) result
end = struct
  type point = Infinity | Point of Field.t * Field.t

  let hex64 z = Z.format "%064x" z

  let generator =
    Point (
      Field.of_z (Z.of_string "0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
      Field.of_z (Z.of_string "0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"))

  (* secp256k1: a = 0, b = 7 *)
  let b = Field.of_z (Z.of_int 7)

  let is_on_curve = function
    | Infinity -> true
    | Point (x, y) ->
      Field.equal (Field.mul y y)
                  (Field.add (Field.mul x (Field.mul x x)) b)

  let neg = function
    | Infinity -> Infinity
    | Point (x, y) -> Point (x, Field.neg y)

  let double = function
    | Infinity -> Infinity
    | Point (x, y) ->
      if Field.is_zero y then Infinity           (* tangent vertical *)
      else
        (* λ = (3x² + a) / (2y) = 3x² / (2y)  because a = 0 *)
        let num = Field.mul (Field.of_z (Z.of_int 3)) (Field.mul x x) in
        let den = Field.mul (Field.of_z (Z.of_int 2)) y in
        (match Field.inv den with
         | Error _ -> Infinity                    (* cannot happen: p prime, y ≠ 0 *)
         | Ok den_inv ->
           let lam = Field.mul num den_inv in
           let x3  = Field.sub (Field.mul lam lam)
                               (Field.mul (Field.of_z (Z.of_int 2)) x) in
           let y3  = Field.sub (Field.mul lam (Field.sub x x3)) y in
           Point (x3, y3))

  let add p q =
    match p, q with
    | Infinity, r | r, Infinity -> r
    | Point (x1, y1), Point (x2, y2) ->
      if Field.equal x1 x2 then
        (* either P = -Q  (then Infinity)  or  P = Q  (then double) *)
        if Field.equal (Field.add y1 y2) Field.zero then Infinity
        else double p
      else
        let num = Field.sub y2 y1 in
        let den = Field.sub x2 x1 in
        (match Field.inv den with
         | Error _ -> Infinity
         | Ok den_inv ->
           let lam = Field.mul num den_inv in
           let x3  = Field.sub (Field.sub (Field.mul lam lam) x1) x2 in
           let y3  = Field.sub (Field.mul lam (Field.sub x1 x3)) y1 in
           Point (x3, y3))

  let scalar_mul k p =
    let k = Scalar.to_z k in
    if Z.sign k < 0 then invalid_arg "Curve.scalar_mul: negative scalar";
    (* plain double-and-add *)
    let rec loop acc addend k =
      if Z.equal k Z.zero then acc
      else
        let acc'    = if Z.testbit k 0 then add acc addend else acc in
        let addend' = double addend in
        loop acc' addend' (Z.shift_right k 1)
    in
    loop Infinity p k

  let equal p q =
    match p, q with
    | Infinity, Infinity -> true
    | Point (x1, y1), Point (x2, y2) ->
      Field.equal x1 x2 && Field.equal y1 y2
    | _ -> false

  let x = function Infinity -> None | Point (x, _) -> Some x
  let y = function Infinity -> None | Point (_, y) -> Some y

  (* ── serialization ──────────────────────────────────────────────── *)
  let to_uncompressed = function
    | Infinity -> "00"
    | Point (x, y) -> "04" ^ hex64 (Field.to_z x) ^ hex64 (Field.to_z y)

  let to_compressed = function
    | Infinity -> "00"
    | Point (x, y) ->
      let prefix = if Z.testbit (Field.to_z y) 0 then "03" else "02" in
      prefix ^ hex64 (Field.to_z x)

  (* p ≡ 3 (mod 4)  ⇒  sqrt(a) = a^((p+1)/4) *)
  let sqrt_mod_p a =
    let exp = Z.div (Z.add Field.modulus Z.one) (Z.of_int 4) in
    let r = Field.pow a exp in
    if Field.equal (Field.mul r r) a then Some r else None

  let of_uncompressed s =
    if String.length s <> 130 then Error "uncompressed: bad length"
    else if String.sub s 0 2 <> "04" then Error "uncompressed: bad prefix"
    else
      match Field.of_hex (String.sub s 2 64),
            Field.of_hex (String.sub s 66 64) with
      | Ok x, Ok y ->
        let p = Point (x, y) in
        if is_on_curve p then Ok p else Error "point not on curve"
      | _ -> Error "uncompressed: bad hex"

  let of_compressed s =
    if String.length s <> 66 then Error "compressed: bad length"
    else
      let prefix = String.sub s 0 2 in
      if prefix <> "02" && prefix <> "03" then Error "compressed: bad prefix"
      else
        match Field.of_hex (String.sub s 2 64) with
        | Error e -> Error e
        | Ok x ->
          let alpha = Field.add (Field.mul x (Field.mul x x)) b in
          (match sqrt_mod_p alpha with
           | None -> Error "compressed: x is not on curve"
           | Some y ->
             let want_odd = (prefix = "03") in
             let y' = if Z.testbit (Field.to_z y) 0 = want_odd
                      then y else Field.neg y in
             Ok (Point (x, y')))
end
