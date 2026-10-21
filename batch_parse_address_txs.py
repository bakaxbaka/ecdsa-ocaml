#!/usr/bin/env python3
"""
Batch parse all transactions from a JSON file created by fetch_address_inputs.py.
Extract r/s signatures for all transactions and outputs to CSV.

Usage: python batch_parse_address_txs.py <input_json> [output_csv]
"""

import sys
import json
import csv
from pathlib import Path

# Import the parser functions
try:
    from parse_rawtx import parse_raw_transaction, parse_script_sig, parse_der_signature
except ImportError:
    print("Error: parse_rawtx.py not found in current directory")
    sys.exit(1)

def parse_all_transactions(input_json):
    """Parse all transactions from JSON file and extract signature data."""
    
    # Load JSON
    with open(input_json, 'r') as f:
        txs = json.load(f)
    
    print(f"Loaded {len(txs)} transactions from {input_json}")
    
    results = []
    
    for i, tx_data in enumerate(txs, 1):
        txid = tx_data['txid']
        raw_hex = tx_data['raw_hex']
        
        print(f"\n[{i}/{len(txs)}] Parsing transaction: {txid}")
        
        try:
            # Parse the transaction
            tx = parse_raw_transaction(raw_hex)
            
            # Extract signatures from each input
            for input_idx, inp in enumerate(tx['inputs']):
                if inp['script_sig']:
                    try:
                        der_sig, pubkey = parse_script_sig(inp['script_sig'])
                        r, s = parse_der_signature(der_sig)
                        
                        results.append({
                            'txid': txid,
                            'input_index': input_idx,
                            'prev_txid': inp['prev_txid'],
                            'prevout': inp['prevout'],
                            'sequence': inp['sequence'],
                            'der_signature': der_sig.hex(),
                            'r': hex(r),
                            's': hex(s),
                            'pubkey': pubkey.hex() if pubkey else '(P2PK)',
                            'script_sig': inp['script_sig'].hex()
                        })
                        
                        print(f"  Input {input_idx}: r={hex(r)[:40]}... s={hex(s)[:40]}...")
                        
                    except Exception as e:
                        print(f"  Input {input_idx}: Error parsing signature - {e}")
                else:
                    print(f"  Input {input_idx}: No scriptSig")
        
        except Exception as e:
            print(f"  Error parsing transaction: {e}")
    
    return results

def save_to_csv(data, output_csv):
    """Save signature data to CSV file."""
    if not data:
        print("No signature data to save")
        return None
    
    output_path = Path(output_csv)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Get field names from first record
    fieldnames = list(data[0].keys())
    
    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)
    
    print(f"\nSaved {len(data)} signature records to: {output_path}")
    return output_path

def main():
    if len(sys.argv) < 2:
        print("Usage: python batch_parse_address_txs.py <input_json> [output_csv]")
        print("\nExample:")
        print("  python batch_parse_address_txs.py input_txs_1FvUkW8thcqG6HP7gAvAjcR52fR7CYodBx.json")
        print("  python batch_parse_address_txs.py input_txs_1FvUkW8thcqG6HP7gAvAjcR52fR7CYodBx.json signatures.csv")
        sys.exit(1)
    
    input_json = sys.argv[1]
    
    # Default output filename
    if len(sys.argv) > 2:
        output_csv = sys.argv[2]
    else:
        # Derive from input filename
        input_path = Path(input_json)
        output_csv = input_path.stem + "_signatures.csv"
    
    print("=" * 60)
    print("Batch Transaction Signature Parser")
    print("=" * 60)
    print()
    
    # Parse all transactions
    results = parse_all_transactions(input_json)
    
    # Save to CSV
    if results:
        save_to_csv(results, output_csv)
        
        # Summary
        print("\n" + "=" * 60)
        print("Summary")
        print("=" * 60)
        print(f"Input file: {input_json}")
        print(f"Total signatures extracted: {len(results)}")
        print(f"Output file: {output_csv}")
        print("\nDone!")
    else:
        print("\nNo signatures extracted")
        sys.exit(1)

if __name__ == "__main__":
    main()
