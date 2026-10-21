# Address Input Transaction Fetcher - fetch_address_inputs.bat

## Overview

`fetch_address_inputs.bat` is a Windows batch file wrapper for a Python script that fetches all spending transactions for a Bitcoin address (transactions where the address appears as an INPUT) and saves the raw transaction hex data to a JSON file.

## Files

- `fetch_address_inputs.bat` - Windows batch file wrapper
- `fetch_address_inputs.py` - Python fetcher implementation

## Usage

### Command Line

```cmd
fetch_address_inputs.bat <address> [output_json]
```

### Interactive Mode

```cmd
fetch_address_inputs.bat
```
Then enter the Bitcoin address when prompted.

## Examples

```cmd
# With default output filename
fetch_address_inputs.bat 1FvUkW8thcqG6HP7gAvAjcR52fR7CYodBx

# With custom output filename
fetch_address_inputs.bat 1FvUkW8thcqG6HP7gAvAjcR52fR7CYodBx my_transactions.json
```

## Output JSON Format

The script creates a JSON file with the following structure:

```json
[
  {
    "txid": "523c3a9aa8f69af7a5b0491eeb4e49be3fb20ca5e5b0a9114e0bbdf273c1a690",
    "address": "1FvUkW8thcqG6HP7gAvAjcR52fR7CYodBx",
    "raw_hex": "01000000078c8b9620b5073ba359dcbc45af1d76ddbee0215349a51952967d518fcf5adf5e...",
    "height": 119882,
    "timestamp": 1303623851,
    "size": 1301,
    "fee": 0,
    "input_count": 7,
    "output_count": 1
  }
]
```

### JSON Fields

- **txid**: Transaction ID (hash)
- **address**: The Bitcoin address being queried
- **raw_hex**: Raw transaction hex string (this is what you feed to `parse_rawtx.py`)
- **height**: Block height (null if unconfirmed)
- **timestamp**: Block timestamp (Unix timestamp, null if unconfirmed)
- **size**: Transaction size in bytes
- **fee**: Transaction fee in satoshis
- **input_count**: Number of inputs in the transaction
- **output_count**: Number of outputs in the transaction

## How It Works

1. **Fetch all transactions**: Queries mempool.space API for all transactions involving the address
2. **Filter for spending transactions**: Identifies transactions where the address appears in the INPUT side (i.e., the address is spending coins)
3. **Fetch raw hex**: For each spending transaction, fetches the raw transaction hex
4. **Save to JSON**: Writes all transactions with metadata to a JSON file

## API Source

The script uses the [mempool.space](https://mempool.space/) API:
- Address transactions: `https://mempool.space/api/address/{address}/txs`
- Raw transaction hex: `https://mempool.space/api/tx/{txid}/hex`

## Example Output

```
============================================================
Bitcoin Address Input Transaction Fetcher
============================================================

Fetching transactions for address: 1FvUkW8thcqG6HP7gAvAjcR52fR7CYodBx
Found 50 total transactions
Found 2 spending transactions (address in inputs)
[1/2] Fetching raw tx: 523c3a9aa8f69af7a5b0491eeb4e49be3fb20ca5e5b0a9114e0bbdf273c1a690
[2/2] Fetching raw tx: d95d58461f2d3fd476db49a741944ced4383a548937bb107d8897ea6053aeda8

Saved 2 transactions to: input_txs_1FvUkW8thcqG6HP7gAvAjcR52fR7CYodBx.json

============================================================
Summary
============================================================
Address: 1FvUkW8thcqG6HP7gAvAjcR52fR7CYodBx
Total spending transactions: 2
Output file: input_txs_1FvUkW8thcqG6HP7gAvAjcR52fR7CYodBx.json

Transaction IDs:
  1. 523c3a9aa8f69af7a5b0491eeb4e49be3fb20ca5e5b0a9114e0bbdf273c1a690
  2. d95d58461f2d3fd476db49a741944ced4383a548937bb107d8897ea6053aeda8

Done!
```

## Integration with Raw Transaction Parser

After fetching transactions with this tool, you can parse them with `parse_rawtx.py`:

```cmd
# Step 1: Fetch transactions
fetch_address_inputs.bat 1FvUkW8thcqG6HP7gAvAjcR52fR7CYodBx

# Step 2: Parse a specific transaction from the JSON
# (You'll need to extract the raw_hex field and pass it to parse_rawtx)
```

Or use Python to process the JSON:

```python
import json

# Load the JSON
with open('input_txs_1FvUkW8thcqG6HP7gAvAjcR52fR7CYodBx.json') as f:
    txs = json.load(f)

# Parse each transaction
for tx in txs:
    raw_hex = tx['raw_hex']
    # Call parse_rawtx with this hex
    # python parse_rawtx.py <raw_hex>
```

## Limitations

- **Bitcoin mainnet only**: Currently only works with Bitcoin mainnet addresses
- **mempool.space API dependency**: Requires internet access and the mempool.space API to be available
- **Rate limiting**: The API may have rate limits for frequent requests
- **No historical queries**: Only fetches current blockchain state, not historical snapshots

## Future Improvements

To make this more comprehensive:

1. **Multi-chain support**: Add support for BCH, BTG, BSV, testnets
2. **Multiple API sources**: Fallback to other blockchain APIs (blockstream.info, blockchain.com)
3. **Batch processing**: Process multiple addresses from a file
4. **CSV export**: Option to export to CSV format instead of JSON
5. **Progress bar**: Better progress indication for large address histories
6. **Caching**: Cache results to avoid re-fetching

## Requirements

- Python 3.6+
- `requests` library (`pip install requests`)
- Internet connection (for mempool.space API)

## Install Dependencies

```cmd
pip install requests
```

## Error Handling

The script handles common errors:
- Invalid address format
- Network errors
- API rate limiting
- Missing transactions

If an error occurs, the script will display a message and exit gracefully.
