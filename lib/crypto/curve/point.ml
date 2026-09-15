type t =
  | Infinity
  | Point of { x : Field.t; y : Field.t }

let b     = Field.of_z (Z.of_int 7)
let two   = Field.of_z (Z.of_int 2)
let three = Field.of_z (Z.of_int 3)

let generator =
  Point {
    x = Field.of_z (Z.of_string
      "0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
    y = Field.of_z (Z.of_string
      "0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
  }

let is_on_curve = function
  | Infinity -> true
  | Point { x; y } ->
    Field.equal (Field.mul y y)
                (Field.add (Field.mul x (Field.mul x x)) b)

let equal a b =
  match a, b with
  | Infinity, Infinity -> true
  | Point p, Point q -> Field.equal p.x q.x && Field.equal p.y q.y
  | _ -> false

let x = function Infinity -> None | Point p -> Some p.x
let y = function Infinity -> None | Point p -> Some p.y

let neg = function
  | Infinity -> Infinity
  | Point p -> Point { p with y = Field.neg p.y }

let double = function
  | Infinity -> Infinity
  | Point p ->
    if Field.is_zero p.y then Infinity
    else
      let num = Field.mul three (Field.mul p.x p.x) in
      let den = Field.mul two p.y in
      (match Field.inv den with
       | Error _ -> Infinity
       | Ok den_inv ->
         let lam = Field.mul num den_inv in
         let x3  = Field.sub (Field.mul lam lam) (Field.mul two p.x) in
         let y3  = Field.sub (Field.mul lam (Field.sub p.x x3)) p.y in
         Point { x = x3; y = y3 })

let add a b =
  match a, b with
  | Infinity, p | p, Infinity -> p
  | Point p, Point q ->
    if Field.equal p.x q.x then
      if Field.equal (Field.add p.y q.y) Field.zero then Infinity
      else double a
    else
      let num = Field.sub q.y p.y in
      let den = Field.sub q.x p.x in
      (match Field.inv den with
       | Error _ -> Infinity
       | Ok den_inv ->
         let lam = Field.mul num den_inv in
         let x3  = Field.sub (Field.sub (Field.mul lam lam) p.x) q.x in
         let y3  = Field.sub (Field.mul lam (Field.sub p.x x3)) p.y in
         Point { x = x3; y = y3 })

let scalar_mul (k : Scalar.t) (p : t) : t =
  let k = Scalar.to_z k in
  if Z.sign k < 0 then invalid_arg "Point.scalar_mul: negative scalar";
  let rec loop acc addend k =
    if Z.equal k Z.zero then acc
    else
      let acc'    = if Z.testbit k 0 then add acc addend else acc in
      let addend' = double addend in
      loop acc' addend' (Z.shift_right k 1)
  in
  loop Infinity p k

let hex64 z = Z.format "%064x" z

let to_uncompressed = function
  | Infinity -> "00"
  | Point p -> "04" ^ hex64 (Field.to_z p.x) ^ hex64 (Field.to_z p.y)

let to_compressed = function
  | Infinity -> "00"
  | Point p ->
    let prefix = if Z.testbit (Field.to_z p.y) 0 then "03" else "02" in
    prefix ^ hex64 (Field.to_z p.x)

let sqrt_mod_p a =
  let exp = Z.div (Z.add Field.modulus Z.one) (Z.of_int 4) in
  let r = Field.pow a exp in
  if Field.equal (Field.mul r r) a then Some r else None

let field_of_hex_coordinate context s =
  try
    let z = Z.of_string ("0x" ^ s) in
    if Z.compare z Field.modulus >= 0 then
      Error (Common.Parse_error.Non_canonical context)
    else
      Ok (Field.of_z z)
  with _ ->
    Error (Common.Parse_error.Bad_hex context)

let of_uncompressed s =
  if String.length s <> 130 then
    Error (Common.Parse_error.Bad_length "point: uncompressed")
  else if String.sub s 0 2 <> "04" then
    Error (Common.Parse_error.Bad_prefix "point: uncompressed")
  else
    match field_of_hex_coordinate "point: uncompressed" (String.sub s 2 64),
          field_of_hex_coordinate "point: uncompressed" (String.sub s 66 64) with
    | Ok x, Ok y ->
      let p = Point { x; y } in
      if is_on_curve p then Ok p
      else Error (Common.Parse_error.Not_on_curve "point: uncompressed")
    | Error e, _ | _, Error e -> Error e

let of_compressed s =
  if String.length s <> 66 then
    Error (Common.Parse_error.Bad_length "point: compressed")
  else
    let prefix = String.sub s 0 2 in
    if prefix <> "02" && prefix <> "03" then
      Error (Common.Parse_error.Bad_prefix "point: compressed")
    else
      match field_of_hex_coordinate "point: compressed" (String.sub s 2 64) with
      | Error e -> Error e
      | Ok x ->
        let alpha = Field.add (Field.mul x (Field.mul x x)) b in
        (match sqrt_mod_p alpha with
         | None -> Error (Common.Parse_error.Not_on_curve "point: compressed")
         | Some y ->
           let want_odd = (prefix = "03") in
           let y' = if Z.testbit (Field.to_z y) 0 = want_odd
                    then y else Field.neg y in
           Ok (Point { x; y = y'}))
