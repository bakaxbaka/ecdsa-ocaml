# Complete ECDSA Signature Analysis Workflow

This document describes the complete workflow for fetching Bitcoin address transactions, extracting ECDSA signatures (r, s), and analyzing them for nonce reuse patterns.

## Tools Overview

### 1. fetch_address_inputs.bat
Fetches all spending transactions for a Bitcoin address and saves raw transaction hex to JSON.

### 2. batch_parse_address_txs.bat
Batch parses all transactions from the JSON file and extracts r/s signatures to CSV.

### 3. parse_rawtx.bat
Parses a single raw transaction hex and displays detailed signature information.

## Complete Workflow

### Step 1: Fetch Transactions

```cmd
fetch_address_inputs.bat 1FvUkW8thcqG6HP7gAvAjcR52fR7CYodBx
```

This creates a JSON file (e.g., `input_txs_1FvUkW8thcqG6HP7gAvAjcR52fR7CYodBx.json`) containing:
- Transaction IDs
- Raw transaction hex
- Block height and timestamp
- Fee and size information

### Step 2: Extract Signatures

```cmd
batch_parse_address_txs.bat input_txs_1FvUkW8thcqG6HP7gAvAjcR52fR7CYodBx.json
```

This creates a CSV file (e.g., `input_txs_1FvUkW8thcqG6HP7gAvAjcR52fR7CYodBx_signatures.csv`) containing:
- Transaction ID
- Input index
- Previous transaction ID
- DER signature
- **r** value (hex)
- **s** value (hex)
- Public key
- ScriptSig

### Step 3: Analyze for Nonce Reuse

Use the CSV output to analyze for nonce reuse patterns:

```python
import pandas as pd

# Load signatures
df = pd.read_csv('input_txs_1FvUkW8thcqG6HP7gAvAjcR52fR7CYodBx_signatures.csv')

# Find duplicate r values
duplicate_r = df[df.duplicated(['r'], keep=False)]
print(f"Found {len(duplicate_r)} signatures with duplicate r values")

# Group by r value
r_groups = df.groupby('r')
for r, group in r_groups:
    if len(group) > 1:
        print(f"\nR value: {r}")
        print(f"  Count: {len(group)}")
        print(f"  Transactions: {group['txid'].tolist()}")
```

### Step 4: Verify Signatures (Optional)

For detailed analysis of a single transaction:

```cmd
parse_rawtx.bat <raw_tx_hex>
```

## Quick Start Example

```cmd
# Fetch transactions for your target address
fetch_address_inputs.bat 1FvUkW8thcqG6HP7gAvAjcR52fR7CYodBx

# Extract all signatures
batch_parse_address_txs.bat input_txs_1FvUkW8thcqG6HP7gAvAjcR52fR7CYodBx.json

# Analyze results
# (Open the CSV in Excel or use Python/Excel to analyze)
```

## CSV Output Format

The CSV file contains the following columns:

| Column | Description |
|--------|-------------|
| txid | Transaction ID |
| input_index | Input index within the transaction |
| prev_txid | Previous transaction ID (prevout) |
| prevout | Previous output index |
| sequence | Sequence number |
| der_signature | DER-encoded signature (hex) |
| r | r value (hex) |
| s | s value (hex) |
| pubkey | Public key (hex) or "(P2PK)" |
| script_sig | ScriptSig (hex) |

## Integration with OCaml Pipeline

To integrate with your existing OCaml signature extraction:

1. **Use the JSON output** as a source of raw transaction hex
2. **Compare results** between Python parser and OCaml extractor
3. **Validate signatures** using both implementations

```python
import json

# Load the JSON
with open('input_txs_1FvUkW8thcqG6HP7gAvAjcR52fR7CYodBx.json') as f:
    txs = json.load(f)

# Extract raw hex for OCaml processing
for tx in txs:
    raw_hex = tx['raw_hex']
    # Feed to OCaml tx_signature_extractor.exe
    # _build/default/bin/tx_signature_extractor.exe <raw_hex>
```

## Sighash (z) Calculation

**Important Limitation:** Accurate sighash (z) calculation requires external prevout data:

- **Legacy transactions**: Need scriptPubKey from previous transaction
- **SegWit transactions**: Need value (satoshis) from previous transaction

The current Python parser uses placeholder zeros for z. For accurate z values:

1. Use the OCaml implementation if it has sighash calculation
2. Implement full prevout fetching via blockchain API
3. Use Bitcoin Core RPC

## Nonce Reuse Detection

Nonce reuse occurs when the same random value (k) is used in multiple signatures. This is detected by finding duplicate **r** values with different **z** (sighash) values.

### Simple Detection

```python
import pandas as pd

df = pd.read_csv('signatures.csv')

# Find r values that appear more than once
r_counts = df['r'].value_counts()
repeated_r = r_counts[r_counts > 1]

print("Potentially reused nonces:")
for r, count in repeated_r.items():
    print(f"  r={r}: {count} occurrences")
```

### Advanced Analysis

For serious nonce reuse detection:

1. Extract accurate z values (using OCaml or prevout fetching)
2. Check if same r appears with different z
3. If so, apply the nonce reuse recovery formula:
   ```
   k = (z1 - z2) / (s1 - s2) mod n
   d = (s*k - z) / r mod n
   ```

## Troubleshooting

### No transactions found
- Verify the address is correct
- Check if the address has any spending transactions
- Ensure internet connection (API dependency)

### Parse errors
- Check if the raw hex is valid
- Verify the transaction format (legacy vs SegWit)
- Some inputs may not have parseable signatures (e.g., coinbase)

### Duplicate R values
- Not all duplicates indicate nonce reuse
- Check if transactions are from chain forks (BTC/BTG)
- Verify different z values before concluding nonce reuse

## Requirements

- Python 3.6+
- `requests` library: `pip install requests`
- Internet connection (for mempool.space API)

## File Summary

| File | Purpose |
|------|---------|
| `fetch_address_inputs.bat` | Batch wrapper for address fetching |
| `fetch_address_inputs.py` | Fetch spending transactions to JSON |
| `batch_parse_address_txs.bat` | Batch wrapper for signature extraction |
| `batch_parse_address_txs.py` | Parse JSON and extract signatures to CSV |
| `parse_rawtx.bat` | Batch wrapper for single transaction parsing |
| `parse_rawtx.py` | Parse single transaction hex |

## Next Steps

To complete your ECDSA forensic pipeline:

1. **Implement accurate sighash calculation** (requires prevout data)
2. **Add multi-chain support** (BCH, BTG, BSV, testnets)
3. **Integrate with OCaml** for cross-verification
4. **Add SageMath verification** for independent ECDSA verification
5. **Create comprehensive reports** with confidence levels
