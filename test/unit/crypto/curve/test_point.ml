let modulus_hex = Z.format "%064x" Field.modulus
let modulus_minus_one_hex = Z.format "%064x" Z.(Field.modulus - one)
let modulus_plus_one_hex = Z.format "%064x" Z.(Field.modulus + one)

let expect_non_canonical name = function
  | Error (Common.Parse_error.Non_canonical _) -> ()
  | Error error ->
    Alcotest.failf "%s: expected non-canonical encoding, got: %s" name
      (Common.Parse_error.to_string error)
  | Ok _ -> Alcotest.failf "%s: expected non-canonical encoding" name

let expect_range_eligible name = function
  | Error (Common.Parse_error.Non_canonical _) ->
    Alcotest.failf "%s: coordinate should pass the canonical range check" name
  | Error _ | Ok _ -> ()

let test_compressed_x_equals_modulus_even () =
  expect_non_canonical "compressed even x = modulus"
    (Curve.Point.of_compressed ("02" ^ modulus_hex))

let test_compressed_x_equals_modulus_odd () =
  expect_non_canonical "compressed odd x = modulus"
    (Curve.Point.of_compressed ("03" ^ modulus_hex))

let test_compressed_x_above_modulus () =
  expect_non_canonical "compressed x = modulus + 1"
    (Curve.Point.of_compressed ("02" ^ modulus_plus_one_hex))

let test_compressed_x_below_modulus_is_range_eligible () =
  expect_range_eligible "compressed x = modulus - 1"
    (Curve.Point.of_compressed ("02" ^ modulus_minus_one_hex))

let test_field_of_hex_rejects_non_canonical_values () =
  Alcotest.(check bool) "modulus rejected" true
    (match Field.of_hex modulus_hex with Error _ -> true | Ok _ -> false);
  Alcotest.(check bool) "modulus plus one rejected" true
    (match Field.of_hex modulus_plus_one_hex with Error _ -> true | Ok _ -> false)

let test_uncompressed_x_equals_modulus () =
  expect_non_canonical "uncompressed x = modulus"
    (Curve.Point.of_uncompressed ("04" ^ modulus_hex ^ String.make 64 '0'))

let test_uncompressed_y_equals_modulus () =
  expect_non_canonical "uncompressed y = modulus"
    (Curve.Point.of_uncompressed ("04" ^ String.make 64 '0' ^ modulus_hex))

let () =
  Alcotest.run "curve" [
    "point decoding", [
      "compressed even x = modulus", `Quick,
        test_compressed_x_equals_modulus_even;
      "compressed odd x = modulus", `Quick,
        test_compressed_x_equals_modulus_odd;
      "compressed x = modulus + 1", `Quick,
        test_compressed_x_above_modulus;
      "compressed x = modulus - 1", `Quick,
        test_compressed_x_below_modulus_is_range_eligible;
      "field hex rejects non-canonical values", `Quick,
        test_field_of_hex_rejects_non_canonical_values;
      "uncompressed x = modulus", `Quick, test_uncompressed_x_equals_modulus;
      "uncompressed y = modulus", `Quick, test_uncompressed_y_equals_modulus;
    ];
  ]
