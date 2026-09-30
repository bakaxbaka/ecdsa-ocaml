# test_results.md

Generated 2026-09-25T04:17:16Z. Deterministic seeds: 20260925 (suite), 777 (PARI sample), fixed BIP vectors.

## Summary

| suite | checks | pass | fail |
|---|---|---|---|
| BIP143/legacy ground-truth vectors (tests/test_sighash_vectors.py) | 40 | 40 | 0 |
| cross-language suite (tests/test_suite.py) | 72 | 72 | 0 |
| chain-data structural verification (5078 txs) | 5×5078 | all | 0 |
| signature verification (OpenSSL, all sigs) | 20449 | 20449 | 0 |
| signature verification (pure-python; target+sample) | 1864 | 1864 | 0 |
| signature verification (PARI/GP; 874 target + 150 sample) | 1024 | 1024 | 0 |
| dual-implementation z agreement | 20449 | 20449 | 0 |
| Rust cwbench selftest | 14 | ALL_PASS | 0 |

## Cross-language suite detail (72 checks)

### bigint_modular — 8/8

- ✅ modexp py==gmpy2
- ✅ modexp py==pari
- ✅ mulmod py==gmpy2==pari
- ✅ 2048bit modexp py==gmpy2
- ✅ rust modexp==python
- ✅ rust modinv==python
- ✅ rust gcd==python
- ✅ rust mulmod==python

### gcd_inverse — 3/3

- ✅ gcd py==gmpy2==pari (20 pairs)
- ✅ inverse py==gmpy2==pari + a*inv==1
- ✅ gmpy2 gcdext Bezout identity

### finite_fields — 4/4

- ✅ sqrt mod p on residues (py pow vs pari sqrt) 10x
- ✅ pari znlog small field consistent
- ✅ Fermat a^(p-1)==1 mod p (5x)
- ✅ sympy GF(2) AES-poly irreducible

### polynomials — 5/5

- ✅ sympy expand == pari leading coeff
- ✅ all coefficients match
- ✅ poly gcd sympy==pari (coefficients)
- ✅ numpy conv == exact
- ✅ factor(2^127-1) sympy==pari

### elliptic_curves — 4/4

- ✅ n*G == infinity (btclib)
- ✅ k*G on-curve + btclib==pari (5 random k)
- ✅ point addition commutative
- ✅ double==self-add

### sha_hmac — 6/6

- ✅ SHA-256 NIST vectors: hashlib==pycryptodome==OpenSSL
- ✅ HMAC-SHA256 RFC4231#1 x3 impls
- ✅ rust sha256(abc)==NIST
- ✅ rust hmac RFC4231#1
- ✅ rust dsha256(hello)==python
- ✅ random 10KB hashlib==pycryptodome

### aes — 3/3

- ✅ AES-128 FIPS-197 vector pycryptodome==OpenSSL
- ✅ rust aes crate == vector
- ✅ AES-128-CBC 4KB roundtrip + cross-impl ciphertext equal

### ecdsa — 7/7

- ✅ btclib sign -> btclib verify
- ✅ btclib sign -> OpenSSL verify
- ✅ OpenSSL sign -> btclib verify
- ✅ wrong z rejected
- ✅ 20 real target sigs re-verified (pure python)
- ✅ rust k256 verifies BIP143 vector
- ✅ rust k256 (n-1)G == -G order check

### rng — 5/5

- ✅ os.urandom 1MB chi2 in [150, 380]
- ✅ os.urandom 1MB all 256 byte values seen
- ✅ python random seeded reproducible
- ✅ numpy default_rng seeded reproducible
- ✅ secrets.token_bytes distinct

### serialization — 4/4

- ✅ 300 real txs parse+reserialize byte-identical & txid match
- ✅ DER encode/parse roundtrip all target sigs
- ✅ JSON roundtrip transactions.jsonl first line
- ✅ rust bincode roundtrip

### octave — 20/20

- ✅ octave exit 0
- ✅ matmul500 sum == numpy
- ✅ matmul500 C(1,1) == numpy
- ✅ matmul500 C(250,250) == numpy
- ✅ matmul500 trace == numpy
- ✅ fft65536 max|y| == numpy
- ✅ fft65536 sum real head == numpy
- ✅ fft65536 |y[1]| == numpy
- ✅ poly conv == numpy exact
- ✅ polyval == numpy exact
- ✅ linear solve sum == numpy
- ✅ eig sum == trace
- ✅ eig max == numpy
- ✅ svd s1 == numpy
- ✅ svd s4 == numpy
- ✅ rank == numpy
- ✅ det == numpy
- ✅ function-file fib(20)==6765
- ✅ roots sum == 6
- ✅ roots prod == 6

### cross_language — 3/3

- ✅ rust selftest ALL_PASS
- ✅ python==pari==gmpy2 numeric agreement (see bigint/gcd sections)
- ✅ python==octave numeric agreement (see octave section)

## Ground-truth vector suite detail (40 checks)

- BIP143 P2WPKH: preimage bytes, sigHash, alt-impl agreement, priv→pub, OpenSSL verify, pure verify, RFC6979 reproduces published signature (7)
- BIP143 P2SH-P2WPKH: same battery (6)
- BIP143 P2SH-P2WSH 6-of-6 × {ALL, NONE, SINGLE, ALL|ACP, NONE|ACP, SINGLE|ACP}: preimage+sigHash+alt agreement (18)
- Legacy P2PK (BIP143 example signed tx): alt agreement, priv→pub, OpenSSL verify via legacy_z, pure verify (4)
- Legacy SIGHASH_SINGLE out-of-range bug: z_bytes=0x01||0×31, z=2^248, sign/verify both engines, BIP143 differs (5)

## Data-pipeline verification (real chain data)

{
 "tx_count": 5078,
 "raw_count": 5078,
 "parsed": 5078,
 "parse_fail": 0,
 "roundtrip_fail": 0,
 "txid_fail": 0,
 "wtxid_fail": 0,
 "size_fail": 0,
 "weight_fail": 0,
 "blockstream_hex_checked": 279,
 "blockstream_hex_mismatch": 0
}

Additional reconciliations: sum of 874 target input values == API spent_txo_sum (211,146,722,021 sats): True;
target sigs == spent_txo_count (874): True; txid sets mempool==blockstream: True; 0 JSON-vs-raw mismatches.

## Tests that failed during development and were fixed (rerun green)

| failure | root cause | fix |
|---|---|---|
| cypari2 pip install | gcc OOM compiling generated gen.c on 1 GB | Debian prebuilt python3-cypari2 + .pth + singleton patch |
| 2053 z_impl_mismatch | sighash_alt stripped raw 0xAB bytes inside pushed pubkeys | opcode-aware _strip_codesep (FindAndDelete semantics) |
| 19528 sigs unattributed | parse_pushes raised on OP_k in multisig scripts | lenient_push_items skipping non-push opcodes |
| ripemd160 wrong digest | right-line round functions F2/F4 swapped | corrected to F5,F4,F3,F2,F1; 209 vectors vs pycryptodome |
| 3 vector-test fails | hand-transcription typos of ANYONECANPAY preimages | parse vectors directly from cached BIP143 spec |
| GP syntax errors | multiline brackets unsupported in script mode; argv not set; t_STR slicing | single-line exprs, getenv() file path, Vec() char vectors |
| Rust E0034/E0599/E0716 | ambiguous new_from_slice; missing trait imports; temporaries | Mac:: qualification; Group/PrimeField imports; let-bindings |
| PARI sqrt error in test | random non-residues | test on guaranteed residues x=a² |
| suite compare bugs | gcdext tuple order; sympy-vs-pari string compare; conv typo | unpack (g,s,t); coefficient comparison; 24 not 25 |

All above were rerun to green after fixing (dependent tests re-executed each time; see logs/fixes.log).
