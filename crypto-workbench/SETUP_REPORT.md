# SETUP_REPORT — reproducible cryptography research workstation

Generated: 2026-09-25T04:17:16Z. Container: Debian 12 (bookworm), root, 2× Intel Xeon 2.50 GHz, 1 GB RAM, no swap, ~10 GB disk.

## Status: OPERATIONAL — all installation, import, compile, execute, numerical and cross-check stages pass.

## System information

```
== SYSTEM INFO ==
Linux c-6ab5de90-01ed1602-8ac2a4611c77 4.19.91-c8dfc93.al7.x86_64 #1 SMP Tue Sep 26 10:25:51 UTC 2023 x86_64 GNU/Linux
Debian GNU/Linux 12 (bookworm)
CPUs: 2
model name	: Intel(R) Xeon(R) Processor @ 2.50GHz
aes avx avx2 sse4_2 
MemTotal:        1083460 kB
SwapTotal:             0 kB
OpenSSL 3.0.20 7 Apr 2026 (Library: OpenSSL 3.0.20 7 Apr 2026)
```

Note: CPU supports `aes`, `avx2` but **not** SHA-NI; OpenSSL uses AVX2 assembly for SHA-256 (see benchmarks).

## Tool versions (verified by execution)

```
== TOOL VERSIONS 2026-09-25T02:54:52Z ==
rustc 1.98.1 (48a229cea 2026-09-01)
cargo 1.98.1 (797e8a9bc 2026-08-05)
Debian clang version 14.0.6
gcc (Debian 12.2.0-14+deb12u1) 12.2.0
g++ (Debian 12.2.0-14+deb12u1) 12.2.0
cmake version 3.25.1
git version 2.39.5
GNU Make 4.3
1.8.1
octave: X11 DISPLAY environment variable not set
octave: disabling GUI features
OpenBLAS WARNING - could not determine the L2 cache size on this system, assuming 256k
GNU Octave, version 7.3.0
                  GP/PARI CALCULATOR Version 2.15.2 (released)
          amd64 running linux (x86-64/GMP-6.2.1 kernel) 64-bit version
Python 3.11.2
pip 26.2.1 from /opt/arena-python/lib/python3.11/site-packages/pip (python 3.11)
curl 7.88.1 (x86_64-pc-linux-gnu) libcurl/7.88.1 OpenSSL/3.0.20 zlib/1.2.13 brotli/1.0.9 zstd/1.5.4 libidn2/2.3.3 libpsl/0.21.2 (+libidn2/2.3.3) libssh2/1.10.0 nghttp2/1.52.0 librtmp/2.3 OpenLDAP/2.5.13
```

## Python packages (import-verified)

| package | version | notes |
|---|---|---|
| numpy | 2.4.6 |
| scipy | 1.17.1 |
| sympy | 1.14.0 |
| matplotlib | 3.11.2 |
| pandas | 3.0.6 |
| gmpy2 | 2.3.1 | built against system GMP 6.2.1 (libgmp-dev) |
| cryptography | 50.0.1 | OpenSSL 3.0.20 backend |
| pycryptodome | 3.23.0 |
| requests | 2.34.2 |
| cypari2 | 2.1.2 (Debian python3-cypari2) | pip sdist build impossible on 1 GB RAM — see fix 004; linked to PARI 2.15.2 |

## Rust

- Toolchain: rustup stable, rustc/cargo 1.98.1, installed at `$HOME/.cargo` (session-local `/tmp/.cargo`).
- Benchmark/selftest crate: `rust/cwbench` (release, LTO, `RUSTFLAGS="-C target-cpu=native"`).
- Crates (audited, well-tested; no production crypto invented): `sha2`, `hmac`, `aes` (RustCrypto), `k256` (secp256k1/ECDSA), `num-bigint`, `num-integer`, `rayon`, `serde`+`bincode`, `hex`.
- `cwbench selftest`: ALL_PASS (NIST SHA-256, RFC 4231 HMAC, FIPS-197 AES, BIP143 ECDSA verify via k256, group-order check, bincode roundtrip).

## Workspace layout

```
~/crypto-workbench/
├── SETUP_REPORT.md TARGET_REPORT.md TRANSACTION_CATALOG.md SIGNATURE_ANALYSIS.md
├── benchmark_results.md test_results.md
├── target/            # chain data: txids.txt, transactions*.jsonl, rawtx/ (5078), rawtx_blockstream/ (279),
│                      # inputs.tsv, outputs.tsv, signatures.tsv, z_values.tsv, schnorr_sigs.tsv, anomalies.tsv,
│                      # preimages/ (874), cache/ (all API responses), vectors/ (BIP141/143)
├── python/            # btclib.py (pure-stdlib primitives), sighash_alt.py (independent 2nd impl)
├── scripts/           # fetch_address.py, fetch_hex.py, parse_extract.py, pari_verify.py,
│                      # analyze_target.py, gen_catalog.py, gen_reports.py, setup_env.sh
├── tests/             # test_sighash_vectors.py (BIP143 ground truth), test_suite.py (72 checks)
├── benchmarks/        # run_benchmarks.py
├── octave/            # check_octave.m, thread_scaling.m, fib_file.m
├── pari/              # verify_sigs.gp, bench.gp
├── rust/cwbench/      # Cargo.toml, src/main.rs
├── chaindata/         # persistence mirror of key target/ artifacts (target/ is name-excluded from snapshots)
├── results/           # target_analysis.json, benchmarks_python.json, figures/*.png
└── logs/              # every install/fetch/test/bench log, fixes.log, test_results.json
```

## Failures encountered and fixed (autonomous error-recovery log)

- `[fix 001] bootstrap: curl/wget absent -> apt-get install curl wget ca-certificates (prereq for rustup + API access)`
- `[fix 002] HOME=/tmp in shells but persistent workspace="$ARENA_WORKSPACE" -> all scripts resolve WB via $ARENA_WORKSPACE; consolidated /tmp/crypto-workbench into workspace; Rust left at /tmp/.cargo (session-local by design, reinstall documented)`
- `[fix 003] background jobs killed when a bash call hits its timeout -> launch with setsid+disown+</dev/null and exit call immediately`
- `[fix 004] pip cypari2 sdist build: gcc "virtual memory exhausted" compiling gen.c (233k lines, 1GB RAM) -> switched to prebuilt Debian python3-cypari2 2.1.2; exposed to /opt/arena-python via site-packages/debian-dist-packages.pth; appended upstream-standard `pari = Pari()` singleton to Debian's reduced __init__.py`
- `[fix 005] transient container-wide spawn ENOMEM during concurrent pip+fetcher -> serialize memory-heavy jobs; keep only one compiler/fetcher at a time`
- `[fix 006] sighash_alt.legacy_z_alt stripped raw 0xAB BYTES from subscript; Core's FindAndDelete removes OP_CODESEPARATOR only at opcode positions -> 2053 false z_impl_mismatch on P2SH multisig; replaced with opcode-aware _strip_codesep(); rerun: 0 mismatches on 20449 sigs`
- `[fix 007] candidate-pubkey extraction for multisig used strict parse_pushes which raises on OP_k opcodes -> 19528 sigs unattributed ("no_pubkey"); added lenient_push_items() skipping non-push opcodes; rerun: 20449/20449 attributed + OpenSSL-verified`
- `[fix 008] test vector transcription typo in ANYONECANPAY preimages (hand-copied zeros) -> vectors now parsed directly from cached BIP143 spec anchored at the 6-of-6 tx; 40/40 pass`
- `[fix 009] MiniTx._rd_vi unpacked a format STRING into (fmt,sz) -> IndexError; fixed fmt lookup`
- `[fix 010] btc1.trezor.io (Blockbook) API unreachable from container: Cloudflare bot-protection interstitial ("Attention Required!") for datacenter IP -> used the two designated API sources (mempool.space primary, blockstream.info cross-check); evidence cached at target/cache/trezor_blockbook_cloudflare_block.html`

## Exact reproduction commands

Full ordered script: `scripts/setup_env.sh` (runs everything below):

```bash
export DEBIAN_FRONTEND=noninteractive
apt-get update && apt-get install -y build-essential clang cmake pkg-config git curl wget \
  python3 python3-pip python3-venv octave libssl-dev libgmp-dev libmpfr-dev libmpc-dev \
  libntl-dev libflint-dev pari-gp ca-certificates libpari-dev python3-cypari2
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"
python3 -m pip install --break-system-packages numpy scipy sympy matplotlib pandas \
  gmpy2 cryptography pycryptodome requests
# cypari2: use Debian prebuilt (pip sdist OOMs 1 GB box); expose + restore singleton:
echo /usr/lib/python3/dist-packages > $(python3 -c 'import sys;print([p for p in sys.path if p.endswith("site-packages")][0])')/debian-dist-packages.pth
printf '\npari = Pari()\n' >> /usr/lib/python3/dist-packages/cypari2/__init__.py
cd rust/cwbench && RUSTFLAGS='-C target-cpu=native' cargo build --release
# pipelines: scripts/fetch_address.py -> scripts/fetch_hex.py both -> scripts/parse_extract.py
#            -> scripts/pari_verify.py -> scripts/analyze_target.py -> scripts/gen_catalog.py
#            -> benchmarks/run_benchmarks.py, gp -q pari/bench.gp, cwbench bench/bench-par
#            -> tests/test_sighash_vectors.py, tests/test_suite.py -> scripts/gen_reports.py
```

## Verification status at sign-off

| stage | result |
|---|---|
| apt/rust/pip installation | complete, all versions verified by execution |
| python imports (10 pkgs) | all OK |
| rust compile (release+LTO) | OK, selftest ALL_PASS |
| octave execution | OK (BLAS/LAPACK: OpenBLAS 0.3.21-pthread) |
| PARI/GP execution | OK (2.15.2, GMP kernel) |
| BIP143/legacy ground-truth vectors | 40/40 |
| cross-language test suite | 72/72 |
| chain-data structural verification | 5078/5078 roundtrip+txid+wtxid+size+weight, 0 fails |
| signature/z verification | 20449/20449 OpenSSL; 874/874 target also pure-python + PARI/GP |

## Security & data-handling statement

- Only public blockchain data was fetched; no credentials/keys were requested, generated for others, stored or transmitted.
- No private-key material was derived or sought at any point; published BIP test vectors are used for validation only.
- All logs and reports were scanned for sensitive material by construction (values written are public chain data only).
