#!/usr/bin/env python3
"""
Fetch all spending transactions for a Bitcoin address (transactions where address appears as INPUT).
Save raw transaction hex data to JSON file.
Supports multiple blockchain APIs with automatic failover.

Usage: python fetch_address_inputs.py <address> [output_json]
"""

import sys
import json
import requests
from pathlib import Path

# Multiple blockchain API endpoints (like SignatureFixer)
BLOCKCHAIN_APIS = [
    {
        'name': 'mempool.space',
        'address_url': 'https://mempool.space/api/address/{address}/txs',
        'raw_tx_url': 'https://mempool.space/api/tx/{txid}/hex'
    },
    {
        'name': 'blockstream.info',
        'address_url': 'https://blockstream.info/api/address/{address}/txs',
        'raw_tx_url': 'https://blockstream.info/api/tx/{txid}/hex'
    },
    {
        'name': 'blockchain.info',
        'address_url': 'https://blockchain.info/address/{address}?format=json',
        'raw_tx_url': 'https://blockchain.info/tx/{txid}?format=hex'
    }
]

def get_address_txs(address, api_config=None):
    """Get all transactions for an address from blockchain API."""
    apis = [api_config] if api_config else BLOCKCHAIN_APIS
    
    for api in apis:
        url = api['address_url'].format(address=address)
        print(f"Trying {api['name']}...")
        
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            # blockchain.info returns different format
            if api['name'] == 'blockchain.info':
                # Convert blockchain.info format to standard format
                txs = []
                for tx in data.get('tx', []):
                    txs.append({
                        'txid': tx['hash'],
                        'status': {'block_height': tx.get('block_height'), 'block_time': tx.get('time')},
                        'size': tx.get('size'),
                        'fee': tx.get('fee'),
                        'vin': tx.get('inputs', []),
                        'vout': tx.get('out', [])
                    })
                return txs, api['name']
            
            return data, api['name']
            
        except requests.RequestException as e:
            print(f"  Failed with {api['name']}: {e}")
            continue
    
    print("All APIs failed")
    return None, None

def get_raw_tx(txid, api_config=None):
    """Get raw transaction hex by txid from blockchain API."""
    apis = [api_config] if api_config else BLOCKCHAIN_APIS
    
    for api in apis:
        url = api['raw_tx_url'].format(txid=txid)
        
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            return response.text.strip(), api['name']
        except requests.RequestException as e:
            continue
    
    return None, None

def is_spending_transaction(tx, address):
    """
    Check if a transaction is a spending transaction for the address.
    Returns True if the address appears in any input's scriptPubKey.
    """
    if 'vin' not in tx:
        return False
    
    for vin in tx['vin']:
        # For coinbase transactions, no prevout
        if 'prevout' not in vin:
            continue
        
        # Check if the prevout scriptPubKey contains the address
        prevout = vin['prevout']
        if 'scriptpubkey_address' in prevout:
            if prevout['scriptpubkey_address'] == address:
                return True
    
    return False

def fetch_input_transactions(address):
    """
    Fetch all transactions where the address appears as an input (spending transactions).
    Returns list of transaction data with raw hex.
    """
    print(f"Fetching transactions for address: {address}")
    
    # Get all transactions for the address (with API failover)
    all_txs, api_name = get_address_txs(address)
    if not all_txs:
        print("No transactions found or error occurred")
        return []
    
    print(f"Found {len(all_txs)} total transactions using {api_name}")
    
    # Filter for spending transactions (where address is in inputs)
    spending_txs = []
    for tx in all_txs:
        if is_spending_transaction(tx, address):
            spending_txs.append(tx)
    
    print(f"Found {len(spending_txs)} spending transactions (address in inputs)")
    
    # Fetch raw hex for each spending transaction
    results = []
    for i, tx in enumerate(spending_txs, 1):
        txid = tx['txid']
        print(f"[{i}/{len(spending_txs)}] Fetching raw tx: {txid}")
        
        raw_hex, raw_api = get_raw_tx(txid)
        if raw_hex:
            results.append({
                'txid': txid,
                'address': address,
                'raw_hex': raw_hex,
                'height': tx.get('status', {}).get('block_height', None),
                'timestamp': tx.get('status', {}).get('block_time', None),
                'size': tx.get('size', None),
                'fee': tx.get('fee', None),
                'input_count': len(tx.get('vin', [])),
                'output_count': len(tx.get('vout', []))
            })
        else:
            print(f"  Failed to fetch raw hex for {txid}")
    
    return results

def save_to_json(data, output_file):
    """Save transaction data to JSON file."""
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"\nSaved {len(data)} transactions to: {output_path}")
    return output_path

def main():
    if len(sys.argv) < 2:
        print("Usage: python fetch_address_inputs.py <address> [output_json]")
        print("\nExample:")
        print("  python fetch_address_inputs.py 1FvUkW8thcqG6HP7gAvAjcR52fR7CYodBx")
        print("  python fetch_address_inputs.py 1FvUkW8thcqG6HP7gAvAjcR52fR7CYodBx output.json")
        sys.exit(1)
    
    address = sys.argv[1]
    
    # Default output filename
    if len(sys.argv) > 2:
        output_file = sys.argv[2]
    else:
        # Create filename from address (sanitize)
        safe_address = address.replace(':', '_').replace('/', '_')
        output_file = f"input_txs_{safe_address}.json"
    
    print("=" * 60)
    print("Bitcoin Address Input Transaction Fetcher")
    print("=" * 60)
    print()
    
    # Fetch input transactions
    results = fetch_input_transactions(address)
    
    if not results:
        print("\nNo spending transactions found for this address")
        sys.exit(0)
    
    # Save to JSON
    save_to_json(results, output_file)
    
    # Summary
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"Address: {address}")
    print(f"Total spending transactions: {len(results)}")
    print(f"Output file: {output_file}")
    print()
    
    # Show first few txids
    print("Transaction IDs:")
    for i, tx in enumerate(results[:5], 1):
        print(f"  {i}. {tx['txid']}")
    if len(results) > 5:
        print(f"  ... and {len(results) - 5} more")
    
    print("\nDone!")

if __name__ == "__main__":
    main()
