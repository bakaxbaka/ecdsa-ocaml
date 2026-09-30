(*
   bin/tx_signature_extractor.ml

   Extract and analyse ECDSA signatures from Bitcoin transactions.

   This tool used to hardcode three absolute paths that exist on no machine,
   ignore its own argv, and walk the raw transaction bytes looking for
   DER-looking runs. That walk is why it reported "Invalid DER format" for
   signatures that are perfectly valid: it scanned the whole serialised
   transaction, so every push length it read was an offset into unrelated data.
   On one input it aborted with Invalid_argument("String.sub / Bytes.sub").

   It now takes its input on the command line and uses the project's own parser
   and extractor, so what it reports is what the library actually found.

   Usage:
     tx_signature_extractor <tx-hex-or-file> [<tx-hex-or-file> ...]
     tx_signature_extractor --help

   Exit codes:
     0  every input parsed
     1  usage error, or no input parsed
     2  some inputs parsed, at least one failed
*)

open Printf

let usage = "\
Bitcoin Transaction Signature Extractor
=======================================

Usage:
  tx_signature_extractor <tx-hex-or-file> [<tx-hex-or-file> ...]

Each argument is either a file holding raw transaction hex, or the raw
transaction hex itself. For every input this prints the transaction's shape and
then each signature the library extracted, with its full r, s and sighash byte.

Exit codes: 0 all inputs parsed, 1 usage error or nothing parsed, 2 partial.
"

(* An argument may be a path or literal hex. *)
let read_input (arg : string) : (string, string) result =
  if Sys.file_exists arg && not (Sys.is_directory arg) then
    try
      let ic = open_in_bin arg in
      let n = in_channel_length ic in
      let s = really_input_string ic n in
      close_in ic;
      Ok (String.trim s)
    with e ->
      Error (Printf.sprintf "could not read %s: %s" arg (Printexc.to_string e))
  else Ok (String.trim arg)

(* Strip an optional 0x prefix and check the remainder is hex. *)
let clean_hex (s : string) : (string, string) result =
  let s =
    if String.length s >= 2 && String.sub s 0 2 = "0x" then
      String.sub s 2 (String.length s - 2)
    else s
  in
  if s = "" then Error "empty input"
  else if String.length s mod 2 <> 0 then
    Error (Printf.sprintf "odd-length hex (%d characters)" (String.length s))
  else begin
    let bad = ref false in
    String.iter
      (fun c ->
         match c with
         | '0' .. '9' | 'a' .. 'f' | 'A' .. 'F' -> ()
         | _ -> bad := true)
      s;
    if !bad then Error "input contains a non-hex character" else Ok s
  end

let report_one (label : string) (arg : string) : bool =
  printf "\n=== %s ===\n" label;
  match read_input arg with
  | Error e -> printf "  %s\n" e; false
  | Ok raw -> (
      match clean_hex raw with
      | Error e -> printf "  %s\n" e; false
      | Ok hex -> (
          match Tx_parser.of_hex hex with
          | Error e ->
            printf "  Not a parseable transaction: %s\n"
              (Common.Parse_error.to_string e);
            false
          | Ok tx ->
            let n_in = List.length tx.inputs in
            let n_out = List.length tx.outputs in
            printf "  version %d, %d input(s), %d output(s), %s, lock_time %d\n"
              tx.version n_in n_out
              (if tx.segwit then "segwit" else "legacy")
              tx.lock_time;

            let total = ref 0 in
            let with_sigs = ref 0 in

            for i = 0 to n_in - 1 do
              match Signature_extraction.extract_single tx i with
              | Error e ->
                printf "  input %d: %s\n" i
                  (Signature_extraction.error_to_string e)
              | Ok ex ->
                if ex.signatures = [] then
                  printf "  input %d: no signature found\n" i
                else begin
                  incr with_sigs;
                  total := !total + List.length ex.signatures;
                  printf "  input %d: %d signature(s)\n" i
                    (List.length ex.signatures);
                  (* Reaching this list means the library's strict DER parser
                     accepted each signature: a malformed one surfaces as
                     Invalid_der above, not here. ECDSA validity additionally
                     needs z, which this tool does not compute, so it is not
                     claimed. *)
                  List.iteri
                    (fun j (s : Signature_extraction.parsed_sig) ->
                       printf "    [%d] r = %s\n" j (Z.to_string s.r);
                       printf "        s = %s\n" (Z.to_string s.s);
                       printf "        sighash byte = 0x%02x\n" s.sighash)
                    ex.signatures;
                  if ex.public_key <> None then
                    printf "        public key present in this input\n"
                end
            done;

            printf "  total: %d signature(s) across %d input(s)\n" !total !with_sigs;
            if !with_sigs > 0 then
              printf
                "  note: ECDSA verification needs z and is not computed here.\n\
                \        Use POST /api/nonce/analyze or POST /api/pipeline for a\n\
                \        verified/failed verdict per input.\n";
            true))

let () =
  let args = Array.to_list Sys.argv |> List.tl in
  match args with
  | [] -> print_string usage; exit 1
  | ("--help" | "-h") :: _ -> print_string usage; exit 0
  | _ ->
    printf "Bitcoin Transaction Signature Extractor\n";
    printf "=======================================\n";
    let results =
      List.mapi
        (fun i a -> report_one (Printf.sprintf "input %d" (i + 1)) a)
        args
    in
    let ok = List.filter (fun x -> x) results in
    printf "\n%d of %d input(s) parsed.\n" (List.length ok) (List.length results);
    if ok = [] then exit 1
    else if List.length ok < List.length results then exit 2
    else exit 0
