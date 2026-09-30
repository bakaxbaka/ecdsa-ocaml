# Bitcoin Transaction Signature Analysis

**Status**: Phase 1 Task (Signature Analysis Tooling)  
**Date**: 2026-09-22  
**Public Key**: `03507a40492642239fc7eae74bc1f1beb15a6079ea3702cfdaeec2268bb00bcbd0`

## Transactions Under Analysis

Three Bitcoin transactions with 20 signatures each (~3KB each):

1. **2427823cf3781149b7b2ff221942e5ef23e86bcc2cc6c10a174ec889a591e031.hex**
   - 20 inputs (20 signatures)
   - All signed with same public key
   
2. **ef95039c03e4e7979b8211bb353fa0d636d4845f5fbcc462eb6ab01b506e5bc2.hex**
   - 20 inputs (20 signatures)
   - All signed with same public key
   
3. **d33ade0feef46c87e0d5422d3410a14d6630b49707fc819bfeda6ed7511b3fd4.hex**
   - 20 inputs (20 signatures)
   - All signed with same public key

**Total**: 60 ECDSA signatures for cryptographic analysis

## Analysis Goals

### 1. Extract Signature Components
From each signature, extract:
- **r** — x-coordinate of ephemeral point R (32 bytes, scalar mod n)
- **s** — signature scalar component (32 bytes, scalar mod n)
- **z** — message hash / SIGHASH (32 bytes, computed per BIP143/legacy)

### 2. Check for Nonce Reuse
**Risk**: If the same nonce (r value) is used to sign two different messages with the same key:
```
r1 = r2  (same nonce)
s1 = k^{-1}(z1 + r*d) mod n
s2 = k^{-1}(z2 + r*d) mod n

Then: d = (z1 - z2) / (s1 - s2) * r  [PRIVATE KEY RECOVERED]
```

**Expected**: All r values are unique (60 different r values)

### 3. Analyze Message Hash Patterns
**Question**: Are all z values (SIGHASH) independent?

**Possible patterns** (all would be unusual):
- Repeated z (same message signed twice)
- Collision in z (cryptographically strong hash, should not happen)
- Arithmetic relationships in z (z1 + z2 = z3, etc.)

**Expected**: All z values are independent (60 different z values)

### 4. Check for Weak Nonce Patterns
Even if all r values are unique, patterns can reveal partial information:
- Biased nonce sampling (e.g., all r < 2^255)
- Low Hamming weight nonces (sparse bit patterns)
- Arithmetic structure (e.g., consecutive r values)

**Expected**: No patterns (uniform random distribution)

## OCaml Tooling

### `tx_signature_extractor.ml` (bin/)
Parses transaction hex and extracts DER-encoded signatures.

**Usage**:
```bash
dune exec bin/tx_signature_extractor
```

**Output**:
```
Transaction size: 3024 bytes
Input count: 20
Found 20 DER-encoded signatures
  Signature 0:
    r: 9a218c466e14ee0a7a0a51313bc1bcfd8da924e5f66bd93efa01781a14c2032b
    s: 3ad746b1e5493f51e729cde5a301f348f2c08a606d73ac434bf2f5bb2cc2465d
  ...

⚠️  WARNING: Repeated r values detected (nonce reuse):
  [if any]

✓ No repeated r values (nonces appear unique)
```

### `sig_analysis.ml` (lib/analysis/signature/)
Analyzes extracted signatures for cryptographic patterns.

**Analyzes**:
- Repeated r values (nonce reuse)
- Repeated z values (same message)
- Same z, different r (message signed multiple times)
- Nonce bias detection

### `analyze_tx_signatures.ml` (bin/)
Full integration: parses transactions, computes SIGHASH, extracts signatures, runs analysis.

## Key Findings to Look For

### 🔴 CRITICAL (If Found)
1. **Repeated r across different transactions** → Nonce reuse, private key at risk
2. **Identical z values** → Same message signed twice (transaction malleability issue)
3. **s1/s2 relationship** → Signature reuse vulnerability

### 🟡 WARNING (If Found)
1. **Biased r values** → Weak random number generation
2. **Low Hamming weight r** → Compressed nonce representation
3. **Arithmetic patterns in r** → Non-random nonce generation

### ✅ EXPECTED (Normal Bitcoin)
1. **All r values unique** → Good random nonce generation
2. **All z values independent** → Correct SIGHASH computation
3. **Uniform distribution** → Strong cryptographic properties

## Mathematical Background

### ECDSA Signature (secp256k1)
```
r = x-coordinate of k*G (k = ephemeral nonce)
s = k^{-1}(z + r*d) mod n  (d = private key, z = message hash)
```

### Nonce Reuse Attack (Known r)
If attacker observes two signatures with same r:
```
s1 = k^{-1}(z1 + r*d)
s2 = k^{-1}(z2 + r*d)

s1 - s2 = k^{-1}(z1 - z2)
k = (z1 - z2) / (s1 - s2)

Then: d = r^{-1}(s*k - z) mod n  [PRIVATE KEY REVEALED]
```

### Recovery from Weak Nonce (Research)
If nonce has bias (e.g., k < 2^128):
- Lattice reduction (LLL) can recover private key
- Requires multiple signatures (~100 with 128-bit leak per signature)
- Reference: [Bleichenbacher, Nguyen]

## Files

- **Transactions**: `analysis/tx_vectors/*.hex`
- **Tooling**: `bin/tx_signature_extractor.ml`, `bin/analyze_tx_signatures.ml`
- **Analysis library**: `lib/analysis/signature/sig_analysis.ml`
- **Build**: `opam exec -- dune build && dune exec bin/tx_signature_extractor`

## References

- SEC 1: Elliptic Curve Cryptography (Certicom)
- BIP143: Transaction Signature Verification (Bitcoin)
- RFC 6979: Deterministic ECDSA (Internet Engineering Task Force)
- Bleichenbacher, D. (1997). "Generating ElGamal Signatures without Knowing the Secret Key"

---

**Next Steps**:
1. ✅ Create extraction tools (DONE)
2. Run extraction and analyze patterns
3. Compute SIGHASH for each input
4. Check for cryptographic weaknesses
5. Report findings with actionable recommendations
