module T = struct
  type t = Z.t
  
  let modulus =
    Z.of_string "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
  
  let of_z z =
    let r = Z.erem z modulus in
    if Z.sign r < 0 then Z.add r modulus else r
  
  let to_z x = x
  
  let zero = Z.zero
  let one  = Z.one
  
  (* Check if a raw integer is in the canonical field range [0, p-1] *)
  let is_canonical z =
    Z.compare z Z.zero >= 0 && Z.compare z modulus < 0
  
  let add x y = of_z Z.(x + y)
  let sub x y = of_z Z.(x - y)
  let mul x y = of_z Z.(x * y)
  
  let neg x = if Z.equal x Z.zero then Z.zero else Z.sub modulus x
  
  let inv x =
    if Z.equal x Z.zero then Error "Cannot invert zero"
    else
      let i = Z.invert x modulus in
      if Z.equal i Z.zero then Error "Element is not invertible"
      else Ok (of_z i)
  
  let pow x exponent =
    if Z.sign exponent < 0 then
      match inv x with
      | Error e -> failwith e
      | Ok x_inv -> Z.powm x_inv (Z.neg exponent) modulus
    else
      Z.powm x exponent modulus
  
  let equal = Z.equal
  let compare = Z.compare
  let is_zero x = Z.equal x Z.zero
  
  let to_hex x = Z.format "%x" x
  
  let of_hex s =
    try
      let s =
        if String.length s >= 2 && String.sub s 0 2 = "0x"
        then String.sub s 2 (String.length s - 2)
        else s
      in
      if s = "" then Error "Empty hexadecimal string"
      else
        let z = Z.of_string ("0x" ^ s) in
<<<<<<< HEAD
        if Z.compare z modulus >= 0 then
          Error "Value out of field range"
        else Ok (of_z z)
=======
        (* Check for non-canonical encoding: coordinates >= p must be rejected *)
        if Z.compare z modulus >= 0 then
          Error "Coordinate out of field range (>= p)"
        else if Z.sign z < 0 then
          Error "Negative coordinate"
        else
          Ok (of_z z)
>>>>>>> d919601fbeee4f3cd7a17a6c32768d0769687a7e
    with _ -> Error "Invalid hexadecimal string"
end

include T