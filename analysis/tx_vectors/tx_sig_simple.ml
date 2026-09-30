#!/usr/bin/env ocaml

(*
   Standalone signature extractor - minimal dependencies
   Run: ocaml unix.cma str.cma zarith.cma tx_sig_simple.ml
*)

(* Hex string to bytes *)
let hex_to_bytes hex_str =
  let len = String.length hex_str in
  if len mod 2 <> 0 then failwith "Odd-length hex";
  let bytes = Bytes.create (len / 2) in
  for i = 0 to (len / 2) - 1 do
    let hex_pair = String.sub hex_str (i * 2) 2 in
    try
      let byte_val = int_of_string ("0x" ^ hex_pair) in
      Bytes.set bytes i (Char.chr (byte_val land 0xff))
    with _ -> 
      Printf.printf "Invalid hex pair: %s at position %d\n" hex_pair (i * 2);
      raise Exit
  done;
  bytes

(* Load hex file *)
let load_hex_file path =
  try
    let ic = open_in path in
    let content = really_input_string ic (in_channel_length ic) in
    close_in ic;
    String.trim content
  with e ->
    Printf.printf "Error reading %s: %s\n" path (Printexc.to_string e);
    ""

(* Convert bytes to hex string *)
let bytes_to_hex b =
  let buf = Buffer.create (Bytes.length b * 2) in
  Bytes.iter (fun c ->
    Buffer.add_string buf (Printf.sprintf "%02x" (Char.code c))
  ) b;
  Buffer.contents buf

(* Extract DER signatures from scriptSig *)
let extract_signatures script_bytes =
  let sigs = ref [] in
  let rec scan pos =
    if pos >= Bytes.length script_bytes - 1 then
      !sigs
    else
      let opcode = Char.code (Bytes.get script_bytes pos) in
      match opcode with
      | n when n >= 1 && n <= 75 && pos + 1 + n <= Bytes.length script_bytes ->
          (* Push n bytes *)
          let data = Bytes.sub script_bytes (pos + 1) n in
          (try
            if Bytes.length data >= 8 then (
              let first = Char.code (Bytes.get data 0) in
              if first = 0x30 then  (* SEQUENCE tag *)
                sigs := (bytes_to_hex data) :: !sigs
            )
          with _ -> ());
          scan (pos + 1 + n)
      | 0x21 ->  (* Push 33 bytes (compressed pubkey) *)
          if pos + 1 + 33 <= Bytes.length script_bytes then
            scan (pos + 1 + 33)
          else
            !sigs
      | _ -> scan (pos + 1)
  in
  scan 0

(* Parse DER signature - extract r and s *)
let parse_der_hex der_hex =
  try
    let der_bytes = hex_to_bytes der_hex in
    let len = Bytes.length der_bytes in
    if len < 8 then None
    else if Char.code (Bytes.get der_bytes 0) <> 0x30 then None
    else
      let total_len = Char.code (Bytes.get der_bytes 1) in
      if total_len + 2 <> len then None
      else
        (* Parse r *)
        let r_tag = Char.code (Bytes.get der_bytes 2) in
        if r_tag <> 0x02 then None
        else
          let r_len = Char.code (Bytes.get der_bytes 3) in
          if r_len <= 0 || 4 + r_len > len then None
          else
            let r_bytes = Bytes.sub der_bytes 4 r_len in
            let r_hex = bytes_to_hex r_bytes in
            
            (* Parse s *)
            let s_offset = 4 + r_len in
            if s_offset + 2 >= len then None
            else
              let s_tag = Char.code (Bytes.get der_bytes s_offset) in
              if s_tag <> 0x02 then None
              else
                let s_len = Char.code (Bytes.get der_bytes (s_offset + 1)) in
                if s_len <= 0 || s_offset + 2 + s_len > len then None
                else
                  let s_bytes = Bytes.sub der_bytes (s_offset + 2) s_len in
                  let s_hex = bytes_to_hex s_bytes in
                  Some (r_hex, s_hex)
  with _ -> None

(* Main *)
let () =
  Printf.printf "Bitcoin Transaction Signature Extractor\n";
  Printf.printf "========================================\n\n";
  
  let tx_files = [
    ("d:\\ecdsa-ocaml\\analysis\\tx_vectors\\2427823cf3781149b7b2ff221942e5ef23e86bcc2cc6c10a174ec889a591e031.hex", "TX1");
    ("d:\\ecdsa-ocaml\\analysis\\tx_vectors\\ef95039c03e4e7979b8211bb353fa0d636d4845f5fbcc462eb6ab01b506e5bc2.hex", "TX2");
    ("d:\\ecdsa-ocaml\\analysis\\tx_vectors\\d33ade0feef46c87e0d5422d3410a14d6630b49707fc819bfeda6ed7511b3fd4.hex", "TX3");
  ] in
  
  let all_signatures = ref [] in
  
  List.iter (fun (path, label) ->
    Printf.printf "\n=== %s ===\n" label;
    
    if Sys.file_exists path then (
      let hex_str = load_hex_file path in
      Printf.printf "Transaction size: %d bytes (%d hex chars)\n" 
        (String.length hex_str / 2) (String.length hex_str);
      
      try
        let tx_bytes = hex_to_bytes hex_str in
        
        (* Extract signatures *)
        let sigs_hex = extract_signatures tx_bytes in
        Printf.printf "Found %d DER-encoded signatures\n" (List.length sigs_hex);
        
        (* Parse each *)
        List.iteri (fun i der_hex ->
          match parse_der_hex der_hex with
          | Some (r, s) ->
              Printf.printf "  [%d] r = %s\n" i r;
              Printf.printf "      s = %s\n" s;
              all_signatures := (label, i, r, s) :: !all_signatures
          | None ->
              Printf.printf "  [%d] Invalid DER format\n" i
        ) sigs_hex
      with e ->
        Printf.printf "Error: %s\n" (Printexc.to_string e)
    ) else
      Printf.printf "File not found: %s\n" path
  ) tx_files;
  
  Printf.printf "\n=== Summary ===\n";
  Printf.printf "Total signatures extracted: %d\n" (List.length !all_signatures);
  
  (* Check for repeated r values *)
  let r_map = Hashtbl.create 100 in
  List.iter (fun (tx_label, idx, r, _s) ->
    let key = Printf.sprintf "%s[%d]" tx_label idx in
    try
      let existing = Hashtbl.find r_map r in
      Printf.printf "⚠️  NONCE REUSE DETECTED!\n";
      Printf.printf "   r = %s\n" r;
      Printf.printf "   Found in: %s\n" existing;
      Printf.printf "   Also in:  %s\n" key
    with Not_found ->
      Hashtbl.add r_map r key
  ) !all_signatures;
  
  Printf.printf "\n✓ Extraction complete.\n"
