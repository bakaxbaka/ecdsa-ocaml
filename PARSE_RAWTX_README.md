# Raw Transaction Parser - parse_rawtx.bat

## Overview

`parse_rawtx.bat` is a Windows batch file wrapper for a Python script that parses raw Bitcoin transaction hex and extracts signature parameters (r, s) and attempts to calculate sighash (z).

## Files

- `parse_rawtx.bat` - Windows batch file wrapper
- `parse_rawtx.py` - Python parser implementation

## Usage

### Command Line

```cmd
parse_rawtx.bat <rawtx_hex> [input_index]
```

### Interactive Mode

```cmd
parse_rawtx.bat
```
Then enter the raw transaction hex when prompted.

## Output

The parser displays:

1. **Transaction Structure**
   - Version
   - Number of inputs
   - Number of outputs
   - Locktime
   - SegWit status

2. **Per-Input Analysis**
   - Previous transaction ID (txid)
   - Previous output index (prevout)
   - Sequence number
   - DER signature (hex)
   - **r** value (hex)
   - **s** value (hex)
   - Public key (if present in scriptSig)
   - Sighash (z) - see limitations below

## Limitations

### Sighash (z) Calculation

**Important:** Accurate sighash calculation requires external data:

- **Legacy transactions (BIP34):** Requires the scriptPubKey of the output being spent (from the previous transaction)
- **SegWit transactions (BIP143):** Requires the value (in satoshis) of the output being spent

The current implementation uses placeholder zeros for z and displays a warning:
```
Warning: Simplified sighash calculation - external prevout data required for accurate z
```

### Why External Data is Required

Bitcoin's sighash algorithm signs over transaction data including the output being spent. This requires:

1. Fetching the previous transaction by its txid
2. Extracting the specific output (by index)
3. Reading either:
   - ScriptPubKey (for legacy sighash)
   - Value (for SegWit sighash)

This is by design - it prevents transaction malleability attacks.

## ScriptSig Formats Supported

The parser handles both P2PKH and P2PK scriptSig formats:

- **P2PKH:** `<DER signature> <pubkey>` - public key is embedded in scriptSig
- **P2PK:** `<DER signature> <sighash_type>` - public key is in prevout scriptPubKey

## DER Signature Parsing

The parser extracts r and s values from DER-encoded signatures:

```
DER format: 0x30 <total_len> 0x02 <r_len> <r> 0x02 <s_len> <s>
```

Values are returned as integers in hexadecimal format.

## Example Output

```
Parsing raw transaction...
Raw TX: 01000000078c8b9620b5073ba359dcbc45af1d76ddbee0215349a51952967d518fcf5adf5e000000...

Version: 1
Inputs: 7
Outputs: 1
Locktime: 0
SegWit: False

--- Input 0 ---
Prev TXID: 5edf5acf8f517d965219a5495321e0bedd761daf45bcdc59a33b07b520968b8c
Prevout: 0
Sequence: 4294967295
Signature (DER): 3044022070aee9c959607de56c500a2aefeaed489aab151daf42299df564106367c296e10220755799de9564d2968ceac7f8a3678d1d7b47e41fadb24ba6c694fc11eae6bcc901
r: 0x70aee9c959607de56c500a2aefeaed489aab151daf42299df564106367c296e1
s: 0x755799de9564d2968ceac7f8a3678d1d7b47e41fadb24ba6c694fc11eae6bcc9
Public Key: (P2PK - embedded in prevout script)
Warning: Simplified sighash calculation - external prevout data required for accurate z
z (sighash): 0000000000000000000000000000000000000000000000000000000000000000
```

## Integration with OCaml Pipeline

To integrate this with the OCaml signature extraction pipeline:

1. Use the Python fetcher to get raw transactions: `fetch_bitcoin.py`
2. Parse with this tool to extract r/s: `parse_rawtx.bat <hex>`
3. For accurate z values, either:
   - Use the OCaml implementation if it has sighash calculation
   - Implement full prevout fetching in Python
   - Use an external tool like Bitcoin Core's RPC

## Future Improvements

To enable accurate sighash calculation:

1. Add prevout transaction fetching via blockchain API
2. Extract scriptPubKey or value from prevout
3. Implement full BIP34 sighash for legacy transactions
4. Implement full BIP143 sighash for SegWit transactions
5. Add support for other sighash types (SIGHASH_SINGLE, SIGHASH_NONE, etc.)

## Requirements

- Python 3.6+
- No external Python dependencies (uses only stdlib)
