#!/usr/bin/env bash
# setup_env.sh — exact, ordered commands to reproduce this crypto research workstation.
# Environment: Debian 12 (bookworm), root, 2 CPU / 1 GB RAM, ~10 GB disk.
# Tested end-to-end on 2026-09-25 (see SETUP_REPORT.md).
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
WB="${ARENA_WORKSPACE:-$HOME}/crypto-workbench"
mkdir -p "$WB"/{target/rawtx,experiments,tests,benchmarks,octave,python,rust,pari,results,logs,scripts}

echo "== [1/6] system packages =="
apt-get update
apt-get install -y build-essential clang cmake pkg-config git curl wget \
  python3 python3-pip python3-venv octave \
  libssl-dev libgmp-dev libmpfr-dev libmpc-dev libntl-dev libflint-dev pari-gp \
  ca-certificates
# cypari2 build dependencies / prebuilt fallback (pip sdist build of cypari2 exhausts
# 1 GB RAM compiling its generated gen.c; the Debian prebuilt package avoids that):
apt-get install -y libpari-dev python3-cypari2

echo "== [2/6] rust toolchain =="
if ! command -v cargo >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
fi
. "$HOME/.cargo/env"

echo "== [3/6] python packages =="
python3 -m pip install --break-system-packages \
  numpy scipy sympy matplotlib pandas gmpy2 cryptography pycryptodome requests
# expose Debian's prebuilt cypari2 to the active interpreter and restore the
# upstream `from cypari2 import pari` singleton (Debian ships a reduced __init__):
SP="$(python3 -c 'import site,sys; print([p for p in sys.path if p.endswith("site-packages")][0])')"
echo "/usr/lib/python3/dist-packages" > "$SP/debian-dist-packages.pth"
if ! python3 -c 'from cypari2 import pari' 2>/dev/null; then
  printf '\npari = Pari()\n__all__ = ["Pari", "PariError", "Gen", "pari"]\n' \
    >> /usr/lib/python3/dist-packages/cypari2/__init__.py
fi

echo "== [4/6] tool verification =="
rustc --version && cargo --version && clang --version | head -1 && gcc --version | head -1
cmake --version | head -1 && git --version && octave --version 2>/dev/null | grep -i "GNU Octave" | head -1
gp --version | head -1 && python3 --version && python3 -m pip --version
python3 - <<'PYEOF'
import importlib
mods = ["numpy","scipy","sympy","matplotlib","pandas","gmpy2","cryptography","Crypto","requests","cypari2"]
for m in mods:
    mod = importlib.import_module(m)
    print(f"import {m}: OK {getattr(mod,'__version__','?')}")
PYEOF

echo "== [5/6] rust benchmark crate =="
cd "$WB/rust/cwbench"
RUSTFLAGS="-C target-cpu=native" cargo build --release
./target/release/cwbench selftest

echo "== [6/6] verification + pipelines (run from $WB) =="
cd "$WB"
python3 python/btclib.py                     # library smoke vectors
python3 tests/test_sighash_vectors.py        # 40 BIP143/legacy ground-truth checks
python3 tests/test_suite.py                  # 72-check cross-language suite
# data acquisition (network; caches everything under target/):
#   python3 scripts/fetch_address.py         # full tx history from both APIs
#   python3 scripts/fetch_hex.py both        # raw hex: all txids + crosscheck subset
#   python3 scripts/parse_extract.py         # parse, extract sigs, reconstruct z, verify
#   python3 scripts/pari_verify.py           # PARI/GP cross-language verification
#   python3 scripts/analyze_target.py        # statistical analysis + figures
#   python3 scripts/gen_catalog.py           # TRANSACTION_CATALOG.md
#   python3 scripts/gen_reports.py           # all markdown reports
#   python3 benchmarks/run_benchmarks.py     # python-side benchmarks
#   gp -q pari/bench.gp                      # PARI benchmarks
#   ./rust/cwbench/target/release/cwbench bench 0.7
echo "SETUP COMPLETE"
