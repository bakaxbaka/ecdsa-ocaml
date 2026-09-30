(*
   bin/test_sig_analysis.ml
   
   Test the fixed signature analysis module against rsz_data.csv
   Validates: hex parsing, placeholder handling, nonce reuse detection, key recovery
*)

open Printf

let () =
  printf "=== Signature Analysis Test ===\n";
  printf "Loading CSV: crypto-workbench/rsz_data.csv\n\n";
  
  let csv_path = "d:\\ecdsa-ocaml\\crypto-workbench\\rsz_data.csv" in
  
  if not (Sys.file_exists csv_path) then (
    eprintf "Error: CSV file not found: %s\n" csv_path;
    exit 1
  );
  
  (* Load signatures from CSV *)
  let sigs = Sig_analysis.load_csv csv_path in
  printf "Loaded %d signatures\n" (List.length sigs);
  
  (* Count by z availability *)
  let with_z = List.filter (fun s -> Option.is_some s.Sig_analysis.z) sigs in
  let without_z = List.filter (fun s -> Option.is_none s.Sig_analysis.z) sigs in
  printf "  With z value: %d\n" (List.length with_z);
  printf "  Without z (NEEDS_PROPER_SIGHASH or missing): %d\n" (List.length without_z);
  
  (* Run analysis *)
  printf "\n--- Running Analysis ---\n";
  let result = Sig_analysis.analyze sigs in
  
  printf "Valid signatures after dedup: %d\n" (List.length result.Sig_analysis.signatures);
  printf "Invalid signatures filtered: %d\n" (List.length result.Sig_analysis.invalid);
  
  (* Print nonce reuse cases *)
  printf "\n";
  Sig_analysis.print_analysis result;
  
  (* If nonces were reused, show recovered keys *)
  if List.length result.Sig_analysis.repeated_r > 0 then (
    printf "\n--- Key Recovery Summary ---\n";
    List.iter (fun (r, group) ->
      let recovered = Sig_analysis.recover_private_keys group in
      if List.length recovered > 0 then (
        printf "r = %s: recovered %d key(s)\n" (Sig_analysis.format_r_hex r) (List.length recovered)
      )
    ) result.Sig_analysis.repeated_r
  );
  
  printf "\n✓ Test complete\n"
