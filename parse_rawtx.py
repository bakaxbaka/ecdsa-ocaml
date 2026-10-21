#!/usr/bin/env python3
"""
Parse raw Bitcoin transaction hex, extract signature (r, s) values, and calculate sighash (z).
Usage: python parse_rawtx.py <rawtx_hex> [input_index]
"""

import sys
import struct
import hashlib

def double_sha256(data):
    """Double SHA-256 hash."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def decode_varint(data, pos):
    """Decode Bitcoin's compact size (varint)."""
    if pos >= len(data):
        raise ValueError("Unexpected end of data at varint")
    b = data[pos]
    if b < 0xfd:
        return b, pos + 1
    elif b == 0xfd:
        if pos + 3 > len(data):
            raise ValueError("Unexpected end of data at varint fd")
        return struct.unpack('<H', data[pos+1:pos+3])[0], pos + 3
    elif b == 0xfe:
        if pos + 5 > len(data):
            raise ValueError("Unexpected end of data at varint fe")
        return struct.unpack('<I', data[pos+1:pos+5])[0], pos + 5
    elif b == 0xff:
        if pos + 9 > len(data):
            raise ValueError("Unexpected end of data at varint ff")
        return struct.unpack('<Q', data[pos+1:pos+9])[0], pos + 9

def parse_script_sig(script_sig):
    """Parse scriptSig to extract DER signature and public key."""
    # Parse for both P2PKH and P2PK formats
    # P2PKH: <DER signature> <pubkey>
    # P2PK: <DER signature> <sighash_type>
    pos = 0
    sig_len, pos = decode_varint(script_sig, pos)
    der_sig = script_sig[pos:pos+sig_len]
    pos += sig_len
    
    # Check if there's more data (could be pubkey or sighash type)
    if pos < len(script_sig):
        # Try to parse as pubkey (for P2PKH)
        remaining = script_sig[pos:]
        if len(remaining) >= 33 and len(remaining) <= 65:
            # Could be a pubkey
            pubkey = remaining
            return der_sig, pubkey
        else:
            # Likely just sighash type (for P2PK)
            return der_sig, None
    
    return der_sig, None

def parse_der_signature(der_sig):
    """Parse DER signature to extract r and s values."""
    # DER format: 0x30 <total_len> 0x02 <r_len> <r> 0x02 <s_len> <s>
    if der_sig[0] != 0x30:
        raise ValueError("Invalid DER signature: not a SEQUENCE")
    
    total_len = der_sig[1]
    pos = 2
    
    # Parse r
    if der_sig[pos] != 0x02:
        raise ValueError("Invalid DER signature: r tag")
    r_len = der_sig[pos + 1]
    r_bytes = der_sig[pos + 2:pos + 2 + r_len]
    pos += 2 + r_len
    
    # Parse s
    if der_sig[pos] != 0x02:
        raise ValueError("Invalid DER signature: s tag")
    s_len = der_sig[pos + 1]
    s_bytes = der_sig[pos + 2:pos + 2 + s_len]
    
    # Convert to integers
    r = int.from_bytes(r_bytes, 'big')
    s = int.from_bytes(s_bytes, 'big')
    
    return r, s

def parse_raw_transaction(rawtx_hex):
    """Parse raw Bitcoin transaction hex."""
    # Remove any whitespace
    rawtx_hex = rawtx_hex.strip()
    data = bytes.fromhex(rawtx_hex)
    pos = 0
    
    if len(data) < 10:
        raise ValueError(f"Transaction too short: {len(data)} bytes")
    
    # Version (4 bytes, little-endian)
    version = struct.unpack('<I', data[pos:pos+4])[0]
    pos += 4
    
    # Marker and flag (for SegWit)
    if pos + 2 < len(data):
        marker = data[pos]
        flag = data[pos + 1]
    else:
        marker = 0
        flag = 0
    
    # Check if SegWit
    is_segwit = (marker == 0x00 and flag == 0x01)
    if is_segwit:
        pos += 2
    
    # Input count
    input_count, pos = decode_varint(data, pos)
    
    inputs = []
    for i in range(input_count):
        # Previous txid (32 bytes, reversed)
        if pos + 32 > len(data):
            raise ValueError(f"Input {i}: insufficient data for prev_txid")
        prev_txid = data[pos:pos+32][::-1].hex()
        pos += 32
        
        # Previous output index (4 bytes, little-endian)
        if pos + 4 > len(data):
            raise ValueError(f"Input {i}: insufficient data for prevout")
        prevout = struct.unpack('<I', data[pos:pos+4])[0]
        pos += 4
        
        # ScriptSig length
        script_len, pos = decode_varint(data, pos)
        
        # ScriptSig
        if pos + script_len > len(data):
            raise ValueError(f"Input {i}: insufficient data for scriptSig")
        script_sig = data[pos:pos+script_len]
        pos += script_len
        
        # Sequence (4 bytes, little-endian)
        if pos + 4 > len(data):
            raise ValueError(f"Input {i}: insufficient data for sequence")
        sequence = struct.unpack('<I', data[pos:pos+4])[0]
        pos += 4
        
        inputs.append({
            'prev_txid': prev_txid,
            'prevout': prevout,
            'script_sig': script_sig,
            'sequence': sequence
        })
    
    # Output count
    output_count, pos = decode_varint(data, pos)
    
    outputs = []
    for i in range(output_count):
        # Value (8 bytes, little-endian)
        if pos + 8 > len(data):
            raise ValueError(f"Output {i}: insufficient data for value")
        value = struct.unpack('<Q', data[pos:pos+8])[0]
        pos += 8
        
        # ScriptPubKey length
        script_len, pos = decode_varint(data, pos)
        
        # ScriptPubKey
        if pos + script_len > len(data):
            raise ValueError(f"Output {i}: insufficient data for scriptPubKey")
        script_pubkey = data[pos:pos+script_len]
        pos += script_len
        
        outputs.append({
            'value': value,
            'script_pubkey': script_pubkey
        })
    
    # Witness data (if SegWit)
    witnesses = []
    if is_segwit:
        for i in range(input_count):
            witness_count, pos = decode_varint(data, pos)
            witness = []
            for j in range(witness_count):
                witness_len, pos = decode_varint(data, pos)
                witness.append(data[pos:pos+witness_len])
                pos += witness_len
            witnesses.append(witness)
    
    # Locktime (4 bytes, little-endian)
    if pos + 4 > len(data):
        raise ValueError("Insufficient data for locktime")
    locktime = struct.unpack('<I', data[pos:pos+4])[0]
    
    return {
        'version': version,
        'inputs': inputs,
        'outputs': outputs,
        'witnesses': witnesses if is_segwit else None,
        'locktime': locktime,
        'is_segwit': is_segwit
    }

def calculate_sighash_bip34(rawtx_hex, input_index, sighash_type=0x01):
    """
    Calculate sighash (z) using BIP34 sighash algorithm (simplified).
    This is a placeholder - full BIP34 sighash requires external prevout data.
    """
    data = bytes.fromhex(rawtx_hex)
    pos = 0
    
    # Version
    version = data[pos:pos+4]
    pos += 4
    
    # Check SegWit
    marker = data[pos]
    flag = data[pos + 1] if pos + 1 < len(data) else 0
    is_segwit = (marker == 0x00 and flag == 0x01)
    
    if is_segwit:
        # For SegWit, use witness v0 sighash
        return calculate_sighash_segwit_v0(rawtx_hex, input_index, sighash_type)
    
    # Skip marker/flag if present
    if is_segwit:
        pos += 2
    
    # This is a simplified implementation
    # Full BIP34 sighash requires prevout scriptPubKey and value from external data
    # For now, return a placeholder hash
    
    print("Warning: Simplified sighash calculation - external prevout data required for accurate z")
    return b'\x00' * 32

def calculate_sighash_segwit_v0(rawtx_hex, input_index, sighash_type=0x01):
    """
    Calculate SegWit v0 sighash (BIP143).
    Note: This requires external prevout value data for accurate calculation.
    """
    data = bytes.fromhex(rawtx_hex)
    pos = 0
    
    # Version
    version = data[pos:pos+4]
    pos += 4
    
    # Skip marker and flag
    pos += 2
    
    # Input count
    input_count, pos = decode_varint(data, pos)
    
    # Parse inputs
    inputs = []
    for i in range(input_count):
        prev_txid = data[pos:pos+32]
        pos += 32
        prevout = data[pos:pos+4]
        pos += 4
        script_len, pos = decode_varint(data, pos)
        script_sig = data[pos:pos+script_len]
        pos += script_len
        sequence = data[pos:pos+4]
        pos += 4
        inputs.append({
            'prev_txid': prev_txid,
            'prevout': prevout,
            'sequence': sequence
        })
    
    # Output count
    output_count, pos = decode_varint(data, pos)
    
    # Parse outputs
    outputs = []
    for i in range(output_count):
        value = data[pos:pos+8]
        pos += 8
        script_len, pos = decode_varint(data, pos)
        script_pubkey = data[pos:pos+script_len]
        pos += script_len
        outputs.append({
            'value': value,
            'script_pubkey': script_pubkey
        })
    
    # Parse witnesses
    witnesses = []
    for i in range(input_count):
        witness_count, pos = decode_varint(data, pos)
        witness = []
        for j in range(witness_count):
            witness_len, pos = decode_varint(data, pos)
            witness.append(data[pos:pos+witness_len])
            pos += witness_len
        witnesses.append(witness)
    
    # Locktime
    locktime = data[pos:pos+4]
    
    # BIP143 sighash preimage
    sighash_preimage = bytearray()
    
    # 1. Version (4 bytes)
    sighash_preimage.extend(version)
    
    # 2. Hash prevouts (32 bytes)
    prevouts_data = bytearray()
    for inp in inputs:
        prevouts_data.extend(inp['prev_txid'])
        prevouts_data.extend(inp['prevout'])
    hash_prevouts = double_sha256(bytes(prevouts_data))
    sighash_preimage.extend(hash_prevouts)
    
    # 3. Hash sequence (32 bytes)
    sequence_data = bytearray()
    for inp in inputs:
        sequence_data.extend(inp['sequence'])
    hash_sequence = double_sha256(bytes(sequence_data))
    sighash_preimage.extend(hash_sequence)
    
    # 4. Outpoint (36 bytes)
    sighash_preimage.extend(inputs[input_index]['prev_txid'])
    sighash_preimage.extend(inputs[input_index]['prevout'])
    
    # 5. ScriptCode (variable)
    # For P2WPKH, this is the serialized pubkey script
    # Get the witness pubkey
    if len(witnesses[input_index]) >= 2:
        pubkey = witnesses[input_index][1]
        # P2WPKH scriptCode: 0x1976a914{20-byte-pubkey-hash}88ac
        pubkey_hash = hashlib.new('ripemd160', hashlib.sha256(pubkey).digest()).digest()
        script_code = bytes([0x19, 0x76, 0xa9, 0x14]) + pubkey_hash + bytes([0x88, 0xac])
        sighash_preimage.extend(bytes([len(script_code)]))
        sighash_preimage.extend(script_code)
    else:
        sighash_preimage.extend(bytes([0]))
    
    # 6. Value (8 bytes)
    # NOTE: This requires external data (the prevout value)
    # For accurate sighash, you need to fetch the prevout transaction and output
    print("Warning: SegWit sighash requires external prevout value - using placeholder")
    sighash_preimage.extend(bytes([0] * 8))
    
    # 7. Sequence (4 bytes)
    sighash_preimage.extend(inputs[input_index]['sequence'])
    
    # 8. Hash outputs (32 bytes)
    outputs_data = bytearray()
    for out in outputs:
        outputs_data.extend(out['value'])
        outputs_data.extend(bytes([len(out['script_pubkey'])]))
        outputs_data.extend(out['script_pubkey'])
    hash_outputs = double_sha256(bytes(outputs_data))
    sighash_preimage.extend(hash_outputs)
    
    # 9. Locktime (4 bytes)
    sighash_preimage.extend(locktime)
    
    # 10. Sighash type (4 bytes)
    sighash_preimage.extend(struct.pack('<I', sighash_type))
    
    # Double SHA256
    z = double_sha256(bytes(sighash_preimage))
    
    return z

def main():
    if len(sys.argv) < 2:
        print("Usage: python parse_rawtx.py <rawtx_hex> [input_index]")
        print("       python parse_rawtx.py <rawtx_hex> <input_index>")
        sys.exit(1)
    
    rawtx_hex = sys.argv[1]
    input_index = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    
    print(f"Parsing raw transaction...")
    print(f"Raw TX: {rawtx_hex[:80]}...")
    print()
    
    # Parse transaction
    tx = parse_raw_transaction(rawtx_hex)
    
    print(f"Version: {tx['version']}")
    print(f"Inputs: {len(tx['inputs'])}")
    print(f"Outputs: {len(tx['outputs'])}")
    print(f"Locktime: {tx['locktime']}")
    print(f"SegWit: {tx['is_segwit']}")
    print()
    
    # Process each input
    for i, inp in enumerate(tx['inputs']):
        print(f"--- Input {i} ---")
        print(f"Prev TXID: {inp['prev_txid']}")
        print(f"Prevout: {inp['prevout']}")
        print(f"Sequence: {inp['sequence']}")
        
        # Try to parse scriptSig
        if inp['script_sig']:
            try:
                der_sig, pubkey = parse_script_sig(inp['script_sig'])
                r, s = parse_der_signature(der_sig)
                
                print(f"Signature (DER): {der_sig.hex()}")
                print(f"r: {hex(r)}")
                print(f"s: {hex(s)}")
                
                if pubkey:
                    print(f"Public Key: {pubkey.hex()}")
                else:
                    print(f"Public Key: (P2PK - embedded in prevout script)")
                
                # Calculate sighash
                try:
                    z = calculate_sighash_bip34(rawtx_hex, i)
                    print(f"z (sighash): {z.hex()}")
                except Exception as e:
                    print(f"Error calculating sighash: {e}")
                
            except Exception as e:
                print(f"Error parsing scriptSig: {e}")
                print(f"ScriptSig: {inp['script_sig'].hex()}")
        
        # Check witness data
        if tx['witnesses'] and i < len(tx['witnesses']):
            witness = tx['witnesses'][i]
            print(f"Witness items: {len(witness)}")
            for j, w in enumerate(witness):
                print(f"  Witness[{j}]: {w.hex()}")
        
        print()
    
    # If specific input requested, show detailed sighash
    if input_index < len(tx['inputs']):
        print(f"--- Detailed Sighash for Input {input_index} ---")
        try:
            z = calculate_sighash_bip34(rawtx_hex, input_index)
            print(f"z: {z.hex()}")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()
