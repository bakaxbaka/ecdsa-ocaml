# benchmark_results.md

Host: 2× Intel Xeon 2.50 GHz (avx2, aes; no SHA-NI), 1 GB RAM, no swap, Debian 12. Generated 2026-09-25T04:17:16Z.
Deterministic seeds; each timed loop ≥0.7–1.5 s after warmup. Raw logs: `logs/bench_*.{log,txt}`, `logs/octave_*`.

## 1. Big integers & modular arithmetic (256-bit unless noted; ops/s)

| workload | CPython int | gmpy2 (GMP 6.2.1) | PARI/GP 2.15.2 | Rust num-bigint (release+native) |
|---|---|---|---|---|
| modmul mod p256k1 | 1,759,890 | 3,769,829 | — | 2678448 |
| modexp e=2^255+7 | — | — | 51,282 | — |
| modexp e=65537 | 123,775 | — | — | 109024 |
| modexp e=256-bit random | 6,605 | 72,412 | ~51,282 (gp binary) | — |
| modexp 2048-bit base / 1024-bit mod | 15,630 | 109,908 | — | — |
| modular inverse (256) | 44,212 | 719,442 | 2,500,000 | 103720 |
| gcd (256) | 331,239 | 817,812 | 1,904,760 | 201062 |
| 4096-bit multiply | — | — | 400,000 | — |

Takeaways: GMP-backed paths (gmpy2, PARI) dominate CPython ints on modexp (≈11× at 256-bit random exponents,
≈7× at 2048-bit); CPython's builtin pow is competitive with num-bigint at e=65537; PARI's gp binary beats its
cypari2 binding (~2×) where per-call Python overhead dominates.

## 2. Hashing / symmetric crypto

| workload | engine | throughput |
|---|---|---|
| SHA-256 16 MB | hashlib (OpenSSL, AVX2) | 386.1 MB/s |
| SHA-256 streamed | pycryptodome | 204.9 MB/s |
| SHA-256 | Rust sha2 crate (target-cpu=native, no SHA-NI on this CPU) | 238.7 MB/s |
| AES-128-CBC 4 MB | pycryptodome | 353.4 MB/s |
| AES-128 ECB block loop | Rust aes crate | 403.6 MB/s |
| double-SHA256 of 32–2000 B preimages | hashlib via btclib | ~20449 sigs z-recomputed in <2 s (pipeline) |

## 3. Elliptic-curve / ECDSA (secp256k1)

| workload | engine | rate |
|---|---|---|
| scalar mult (256-bit) | btclib pure-python (reference) | 420/s |
| scalar mult | PARI ellmul | 3,960/s |
| scalar mult | Rust k256 | 15,442/s |
| ECDSA verify | pure-python btclib | 203/s |
| ECDSA verify | OpenSSL via cryptography | 2,240/s |
| ECDSA verify | Rust k256 | 9,590/s |
| ECDSA sign | OpenSSL via cryptography | 1,953/s |
| ECDSA sign | Rust k256 | 16,858/s |
| full pipeline (20,449 sigs: parse+z+2 impls+OpenSSL verify) | CPython | 50.2 s |
| PARI/GP verify 1,024 sigs (incl. point decompression) | gp binary | 1.5 s |

## 4. Matrix / FFT / polynomial

| workload | engine | result |
|---|---|---|
| matmul 256³/512³/1000³ | numpy (OpenBLAS wheel, default threads) | 36.13 / 49.04 / 82.02 GFLOPS |
| matmul 2048³ | Octave + Debian OpenBLAS 0.3.21, 1 thread | 84.132 GFLOPS (0.204201 s) |
| matmul 2048³ | Octave, 2 threads | 73.217 GFLOPS (0.234643 s) |
| FFT 2^20 complex128 | numpy.fft | 13.12/s (110.0 MB/s) |
| FFT 2^20 | scipy.fft | 45.22/s |
| FFT 2^22 | Octave (FFTW) | 0.119305 s (1T) / 0.115021 s (2T env; FFTW single-threaded) |
| poly mul deg-40 (Z[x]) | sympy | 42,047/s |
| poly gcd deg-40 | sympy | 527/s |
| poly mul deg-100 | PARI | 109,890/s |
| poly gcd deg-~101 | PARI | 20,000/s |

## 5. Number-theory research primitives (PARI/GP)

- isprime(2^256−189±2i): 5.00000 µs/op
- factor(2^127−1): 13,333/s
- znlog mod p≈10^6: 60.0000 µs/op
- 50000!: 5.00000 ms
- sympy factorint(60-bit semiprime): 0.50 ms

## 6. Serialization

- Python json roundtrip (real tx object): 25,857/s; pickle: 93,342/s
- Rust serde+bincode roundtrip: 4,978,505/s (~193× vs Python json)
- Raw tx parse+reserialize (btclib, ~400 B avg): 5,078 txs in <8 s incl. all hashing

## 7. Parallelism — measured, then configured conservatively

| probe | single | parallel | verdict |
|---|---|---|---|
| SHA-256 Python multiprocessing | 344.2 MB/s | 444.0 MB/s (2 procs) | ×1.29 — marginal; use only for large independent batches |
| SHA-256 Rust rayon | 228.5 MB/s (1T) | 226.2 MB/s (2T) | ×0.99 — no benefit; keep single-thread |
| OpenBLAS matmul 2048³ | 84.132 GFLOPS (1T) | 73.217 GFLOPS (2T) | 1 thread WINS → set OPENBLAS_NUM_THREADS=1 |
| I/O-bound API fetching | — | 4+2 workers, jittered ~6–8 req/s | big win (5078 hex in ~8 min); thread pool ≤4 per host |

**Defaults adopted:** compute stays single-threaded (BLAS threads pinned to 1; rayon unused; no CPU oversubscription);
multiprocessing reserved for I/O-bound fetching (≤4 concurrent per API host, exponential backoff, full caching).
Memory guard: 1 GB box — heavy jobs serialized (a concurrent cypari2 gcc build once OOMed the container; see fixes.log).
