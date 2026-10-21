#!/usr/bin/env python3
"""
Console interface for ECDSA signature analysis pipeline.
Simple command-line tool for fetching and parsing Bitcoin transactions.
"""

import sys
import os

def print_header():
    print("=" * 70)
    print("           ECDSA Signature Analysis Pipeline - Console")
    print("=" * 70)
    print()

def print_menu():
    print("Options:")
    print("  1. Fetch address transactions")
    print("  2. Parse transactions to extract signatures")
    print("  3. Parse single transaction")
    print("  4. Run complete pipeline (fetch + parse)")
    print("  5. Exit")
    print()

def fetch_transactions():
    print("\n--- Fetch Address Transactions ---")
    address = input("Enter Bitcoin address: ").strip()
    
    if not address:
        print("Error: No address provided")
        return
    
    output_file = input("Enter output JSON filename (press Enter for default): ").strip()
    if not output_file:
        safe_address = address.replace(':', '_').replace('/', '_')
        output_file = f"input_txs_{safe_address}.json"
    
    # Call the fetch script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    script_path = os.path.join(script_dir, 'fetch_address_inputs.py')
    
    import subprocess
    cmd = [sys.executable, script_path, address, output_file]
    subprocess.run(cmd)

def parse_transactions():
    print("\n--- Parse Transactions ---")
    
    # List available JSON files
    script_dir = os.path.dirname(os.path.abspath(__file__))
    json_files = [f for f in os.listdir(script_dir) if f.endswith('.json')]
    
    if not json_files:
        print("No JSON files found. Please fetch transactions first.")
        return
    
    print("Available JSON files:")
    for i, f in enumerate(json_files, 1):
        print(f"  {i}. {f}")
    
    choice = input("Enter file number or filename: ").strip()
    
    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(json_files):
            input_file = json_files[idx]
        else:
            print("Invalid choice")
            return
    else:
        input_file = choice
    
    input_path = os.path.join(script_dir, input_file)
    if not os.path.exists(input_path):
        print(f"File not found: {input_file}")
        return
    
    output_file = input("Enter output CSV filename (press Enter for default): ").strip()
    if not output_file:
        output_file = input_file.replace('.json', '_signatures.csv')
    
    # Call the parse script
    script_path = os.path.join(script_dir, 'batch_parse_address_txs.py')
    
    import subprocess
    cmd = [sys.executable, script_path, input_path, output_file]
    subprocess.run(cmd)

def parse_single_transaction():
    print("\n--- Parse Single Transaction ---")
    raw_hex = input("Enter raw transaction hex: ").strip()
    
    if not raw_hex:
        print("Error: No hex provided")
        return
    
    input_index = input("Enter input index (press Enter for 0): ").strip()
    if not input_index:
        input_index = "0"
    
    # Call the parse script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    script_path = os.path.join(script_dir, 'parse_rawtx.py')
    
    import subprocess
    cmd = [sys.executable, script_path, raw_hex, input_index]
    subprocess.run(cmd)

def run_complete_pipeline():
    print("\n--- Complete Pipeline ---")
    address = input("Enter Bitcoin address: ").strip()
    
    if not address:
        print("Error: No address provided")
        return
    
    safe_address = address.replace(':', '_').replace('/', '_')
    json_file = f"input_txs_{safe_address}.json"
    csv_file = f"input_txs_{safe_address}_signatures.csv"
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Step 1: Fetch
    print("\nStep 1: Fetching transactions...")
    fetch_script = os.path.join(script_dir, 'fetch_address_inputs.py')
    import subprocess
    subprocess.run([sys.executable, fetch_script, address, json_file])
    
    # Step 2: Parse
    print("\nStep 2: Parsing signatures...")
    parse_script = os.path.join(script_dir, 'batch_parse_address_txs.py')
    subprocess.run([sys.executable, parse_script, json_file, csv_file])
    
    print("\n--- Pipeline Complete ---")
    print(f"JSON file: {json_file}")
    print(f"CSV file: {csv_file}")

def main():
    print_header()
    
    while True:
        print_menu()
        choice = input("Select option (1-5): ").strip()
        
        if choice == "1":
            fetch_transactions()
        elif choice == "2":
            parse_transactions()
        elif choice == "3":
            parse_single_transaction()
        elif choice == "4":
            run_complete_pipeline()
        elif choice == "5":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")
        
        input("\nPress Enter to continue...")
        print()

if __name__ == "__main__":
    main()
