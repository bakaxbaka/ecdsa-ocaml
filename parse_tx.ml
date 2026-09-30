(* parse_tx.ml - Simple transaction parser test *)
open Hex
open Transaction.Parser
open Common.Parse_error

let () =
  let hex = "0100000004c5e232b612eb27413aee5669d85c760592b0358fdfd5640951b61cd198291799010000006b4830450221008622d9f5d8ce6251332c5c8bc4ca7d4fbedf5ed0085554cb201885ff5886ec23022048614aeb7b90282fa0b70915e601638e4d0a19c9441d7490ef562c6c998b04020121029f740f6b10458b3d410afce3285411d5d060413fda946d7b3bcd03ad18ff8b96ffffffff0ddbb175f8a2594e8e9d3ea8465006109b7ed9daa569be4e7690ed44fd8938bf010000006b483045022100e8d8ecbdc05d0272dc353b8f1185f6f136ea2f4ea7ce890216e78ca8fae6846d02200739dded6d359049d6ec7f6ef232b240cdfb10e9bd954254e6ec7b858a09f15c01210330ff072aa0aac42562e71dfd2578579dcb7cc2b138d34f67cf3711d12461da3effffffff95c0b367a6ef7c3f8304d390347631131bde9321c45384de35b3c5bb888cabfc010000006b483045022100a8aae4a6b762ecc3341f5da43ee0b22eafcec15ee0cfa356635495def4c028ff0220375e2f73a36a783e6ed41d1d8e4282286f116ebac6fdbb930ad9a35cca16353e0121029f740f6b10458b3d410afce3285411d5d060413fda946d7b3bcd03ad18ff8b96ffffffff75817fea49ed138af25d74c855900f94e7e2ef9ccfe2dfcef1a97ace9e9784fd000000006a47304402205615f15c2277f747b85a91327f27ca608c2731eae30a9a9fceea43a356117a5f0220564c351157ede1e6008d012e3929ea5d8e1184224d452bb6830d7e92b9cbe3010121029f740f6b10458b3d410afce3285411d5d060413fda946d7b3bcd03ad18ff8b96ffffffff029ab4de00000000001976a914dd948a80f5c628fcf5dfeb68dccc294d1bf3161988ac00e1f5050000000017a914d8194dcb82e7deb3e2ae12c10b5fa2c8c5a447448700000000" in
  
  match Hex.to_bytes hex with
  | Error e -> print_endline ("Hex parse error: " ^ (Hex.error_to_string e))
  | Ok bytes ->
    match Transaction.Parser.of_bytes bytes with
    | Error e -> print_endline ("Transaction parse error: " ^ (Parse_error.to_string e))
    | Ok tx ->
      Printf.printf "Transaction parsed successfully:\n";
      Printf.printf "  Version: %d\n" tx.Types.version;
      Printf.printf "  Inputs: %d\n" (List.length tx.Types.inputs);
      Printf.printf "  Outputs: %d\n" (List.length tx.Types.outputs);
      Printf.printf "  SegWit: %b\n" tx.Types.segwit;
      Printf.printf "  Lock time: %d\n" tx.Types.lock_time;
      List.iteri (fun i inp ->
        Printf.printf "\n  Input %d:\n" i;
        Printf.printf "    ScriptSig length: %d\n" (Bytes.length inp.Script_sig);
        Printf.printf "    Sequence: 0x%08x\n" inp.Sequence
      ) tx.Types.inputs;
      List.iteri (fun i out ->
        Printf.printf "\n  Output %d:\n" i;
        Printf.printf "    Value: %Ld satoshis\n" out.Types.value;
        Printf.printf "    ScriptPubKey length: %d\n" (Bytes.length out.Types.script_pubkey)
      ) tx.Types.outputs
