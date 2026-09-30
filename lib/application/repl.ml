open Common
open Transaction_analysis
open Nonce_checker

let run () =
  let state = create_state () in
  Printf.printf "Bitcoin Nonce Analyzer started. Enter transaction hex (Ctrl+C to exit):\n";
  
  try
    while true do
      Printf.printf "> ";
      let input = read_line () in
      match parse_transaction input with
      | Ok (tx, _) ->
          if is_repeated_nonce state tx then
            Printf.printf "Result: Repeated nonce detected! (Hash: %s)\n" tx.hash
          else
            Printf.printf "Result: Nonce is unique. (Hash: %s)\n" tx.hash;
          update_recent_nonces state tx
      | Error e -> 
          Printf.printf "Error: %s\n" (Parse_error.to_string e)
    done
  with
  | End_of_file -> Printf.printf "\nExiting...\n"
