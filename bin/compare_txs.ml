(* bin/compare_txs.ml
   Bitcoin transaction signature comparison tool.

   Builds observations from raw transactions, extracts ECDSA signatures,
   computes z values, and produces a cryptographic relationship analysis.

   Usage: dune exec -- bin/compare_txs.exe <tx1_hex> <tx2_hex> <tx3_hex>

   Each hex string should be a complete raw Bitcoin transaction.
*)

let () =
  Printf.printf "Bitcoin ECDSA Signature Analysis Tool\n";
  Printf.printf "=======================================\n";
  Printf.printf "This binary is under construction.\n";
  Printf.printf "See lib/analysis/signature/observation.ml for the core pipeline.\n"