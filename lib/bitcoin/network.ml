type network = 
  | Mainnet 
  | Testnet 
  | Regtest

type network_params = {
  address_prefix : int;
  wif_prefix : int;
  bech32_hrp : string;
}

let get_params = function
  | Mainnet -> { address_prefix = 0x00; wif_prefix = 0x80; bech32_hrp = "bc" }
  | Testnet -> { address_prefix = 0x6f; wif_prefix = 0x9f; bech32_hrp = "tb" }
  | Regtest -> { address_prefix = 0x6f; wif_prefix = 0x9f; bech32_hrp = "rt" }
