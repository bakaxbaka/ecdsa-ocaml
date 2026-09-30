#!/usr/bin/env python3
"""run_benchmarks.py — representative workload benchmarks (task spec).

Big integers, modular arithmetic, GCD/inverse, finite fields, SHA-256, FFT,
polynomial arithmetic, matrix operations, EC reference ops. Single-threaded
baseline + conservative parallel probes (2 CPU box; never oversubscribe).
Deterministic seeds. Results -> results/benchmarks_python.json
"""
import hashlib, json, math, os, random, sys, time
from concurrent.futures import ProcessPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
WB = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(WB, "python"))
import btclib as B

SEED = 20260925
random.seed(SEED)
R = {}

def bench(fn, budget=1.0, warmup=0.05):
    t0 = time.perf_counter()
    fn()
    w = time.perf_counter() - t0
    if w < 1e-9: w = 1e-9
    est = max(1, int(budget / w))
    t0 = time.perf_counter()
    for _ in range(est):
        fn()
    dt = time.perf_counter() - t0
    return est / dt, dt

def sha_workload(nbytes):
    data = os.urandom(nbytes)
    t0 = time.perf_counter()
    h = hashlib.sha256(data).hexdigest()
    dt = time.perf_counter() - t0
    return (nbytes / dt / 1e6, h)

def _mp_sha_chunk(args):
    n, seed = args
    rnd = random.Random(seed)
    data = bytes(rnd.getrandbits(8) for _ in range(min(n, 1 << 20)))
    reps = max(1, n // len(data))
    t0 = time.perf_counter()
    acc = 0
    for _ in range(reps):
        acc ^= hashlib.sha256(data).digest()[0]
    dt = time.perf_counter() - t0
    return len(data) * reps / dt / 1e6

def main():
    p = B.P; n = B.N
    a256 = random.getrandbits(256) % p
    b256 = random.getrandbits(256) % p
    e256 = random.getrandbits(256)
    a2048 = random.getrandbits(2048)
    m1024 = random.getrandbits(1024) | 1

    # --- big ints / modular arithmetic: native int ---
    R["py_modmul_256_ops_s"], _ = bench(lambda: (a256 * b256) % p)
    R["py_modexp256_e256_ops_s"], _ = bench(lambda: pow(a256, e256, p))
    R["py_modexp256_e65537_ops_s"], _ = bench(lambda: pow(a256, 65537, p))
    R["py_modinv_256_ops_s"], _ = bench(lambda: pow(a256, -1, p))
    R["py_gcd_256_ops_s"], _ = bench(lambda: math.gcd(a256, b256))
    R["py_modexp2048_ops_s"], _ = bench(lambda: pow(a2048, 65537, m1024), budget=1.5)

    # --- gmpy2 ---
    try:
        import gmpy2
        ga, gb, gp, ge = gmpy2.mpz(a256), gmpy2.mpz(b256), gmpy2.mpz(p), gmpy2.mpz(e256)
        R["gmpy2_modmul_256_ops_s"], _ = bench(lambda: gmpy2.powmod(ga, gb, gp) if False else (ga * gb) % gp)
        R["gmpy2_modexp256_ops_s"], _ = bench(lambda: gmpy2.powmod(ga, ge, gp))
        R["gmpy2_modinv_ops_s"], _ = bench(lambda: gmpy2.invert(ga, gp))
        R["gmpy2_gcd_ops_s"], _ = bench(lambda: gmpy2.gcd(ga, gb))
        R["gmpy2_modexp2048_ops_s"], _ = bench(lambda: gmpy2.powmod(gmpy2.mpz(a2048), 65537, gmpy2.mpz(m1024)), budget=1.5)
        R["gmpy2_version"] = gmpy2.version()
    except Exception as e:
        R["gmpy2_error"] = str(e)

    # --- cypari2 ---
    try:
        from cypari2 import pari
        R["pari_modexp256_ops_s"], _ = bench(lambda: pari(f"lift(Mod({a256},{p})^{e256})"))
        R["pari_modinv_ops_s"], _ = bench(lambda: pari(f"lift(1/Mod({a256},{p}))"))
        R["pari_gcd_ops_s"], _ = bench(lambda: pari(f"gcd({a256},{b256})"))
        R["pari_isprime256_ops_s"], _ = bench(lambda: pari("isprime(2^256-189)"), budget=1.5)
        R["pari_factor127_ops_s"], _ = bench(lambda: pari("factor(2^127-1)"), budget=1.5)
        t0 = time.perf_counter(); pari("znlog(Mod(3,1009), Mod(11,1009))"); R["pari_znlog1009_s"] = time.perf_counter() - t0
        t0 = time.perf_counter(); pari(f"E=ellinit([0,7]*Mod(1,{p})); ellmul(E,[Mod({B.Gx},{p}),Mod({B.Gy},{p})],{random.randrange(1,n)})"); R["pari_ec_scalarmult_s"] = time.perf_counter() - t0
    except Exception as e:
        R["pari_error"] = str(e)

    # --- finite fields: sqrt mod p ---
    xf = random.randrange(1, p)
    R["py_field_sqrt_ops_s"], _ = bench(lambda: pow(xf, (p + 1) // 4, p))

    # --- hashing ---
    mbps, _ = sha_workload(16 << 20)
    R["py_sha256_MB_s"] = round(mbps, 1)
    try:
        from Crypto.Hash import SHA256 as CS
        def _c():
            h = CS.new()
            for _ in range(64): h.update(b"\x5a" * 65536)
            h.hexdigest()
        R["pycryptodome_sha256_MB_s"], _ = bench(_c, budget=1.0)
        R["pycryptodome_sha256_MB_s"] = round(R["pycryptodome_sha256_MB_s"] * 4.194304, 1)
    except Exception as e:
        R["pycryptodome_sha_err"] = str(e)

    # --- AES ---
    try:
        from Crypto.Cipher import AES
        c = AES.new(bytes(16), AES.MODE_CBC, bytes(16))
        blob = b"\x5a" * (4 << 20)
        t0 = time.perf_counter(); c.encrypt(blob); dt = time.perf_counter() - t0
        R["pycryptodome_aes128cbc_MB_s"] = round(len(blob) / dt / 1e6, 1)
    except Exception as e:
        R["aes_err"] = str(e)

    # --- EC ops: pure python reference (btclib) vs OpenSSL (cryptography) ---
    k = random.randrange(1, n)
    R["btclib_scalarmult_ops_s"], _ = bench(lambda: B.scalar_mult(k, B.G), budget=1.0)
    priv = random.randrange(1, n)
    z = int.from_bytes(hashlib.sha256(b"bench").digest(), "big")
    r_, s_ = B.ecdsa_sign(priv, z)
    pk = B.pubkey_from_priv(priv)
    R["btclib_ecdsa_verify_ops_s"], _ = bench(lambda: B.ecdsa_verify(pk, z, r_, s_), budget=1.0)
    try:
        from cryptography.hazmat.primitives.asymmetric import ec, utils
        from cryptography.hazmat.primitives import hashes
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pk)
        der = B.der_encode(r_, s_)
        zb = z.to_bytes(32, "big")
        R["openssl_ecdsa_verify_ops_s"], _ = bench(lambda: pub.verify(der, zb, ec.ECDSA(utils.Prehashed(hashes.SHA256()))))
        sk = ec.derive_private_key(priv, ec.SECP256K1())
        R["openssl_ecdsa_sign_ops_s"], _ = bench(lambda: sk.sign(zb, ec.ECDSA(utils.Prehashed(hashes.SHA256()))))
    except Exception as e:
        R["openssl_ec_err"] = str(e)

    # --- numpy matrices / FFT ---
    try:
        import numpy as np
        for sz in (256, 512, 1000):
            A = (np.arange(1, sz*sz+1, dtype=np.float64).reshape(sz, sz) / (sz*sz+1))
            ops, dt = bench(lambda: A @ A.T, budget=1.5)
            R[f"numpy_matmul{sz}_gflops"] = round(2 * sz**3 * ops / 1e9, 2)
        x = np.sin(2*np.pi*np.arange(1 << 20)/97)
        ops, _ = bench(lambda: np.fft.fft(x), budget=1.5)
        R["numpy_fft1M_ops_s"] = round(ops, 2)
        R["numpy_fft1M_MB_s"] = round(ops * (1 << 20) * 8 / 1e6, 1)
        from scipy.fft import fft as sfft
        ops, _ = bench(lambda: sfft(x), budget=1.5)
        R["scipy_fft1M_ops_s"] = round(ops, 2)
    except Exception as e:
        R["numpy_err"] = str(e)

    # --- sympy polynomial arithmetic ---
    try:
        import sympy
        xx = sympy.Symbol('x')
        f = sum(sympy.Integer(random.randrange(1000)) * xx**i for i in range(40))
        g = sum(sympy.Integer(random.randrange(1000)) * xx**i for i in range(40))
        R["sympy_polymul40_ops_s"], _ = bench(lambda: sympy.expand(f * g), budget=1.0)
        R["sympy_polygcd_ops_s"], _ = bench(lambda: sympy.gcd(f * g, f), budget=1.0)
        R["sympy_factorint_2p60_s"] = None
        semip = 1000000007 * 1000000009
        t0 = time.perf_counter(); sympy.factorint(semip); R["sympy_factorint_2p60_s"] = round(time.perf_counter()-t0, 4)
    except Exception as e:
        R["sympy_err"] = str(e)

    # --- serialization ---
    tx = json.loads(open(os.path.join(WB, "target", "transactions.jsonl")).readline())
    R["py_json_roundtrip_ops_s"], _ = bench(lambda: json.loads(json.dumps(tx)))
    import pickle
    R["py_pickle_roundtrip_ops_s"], _ = bench(lambda: pickle.loads(pickle.dumps(tx)))

    # --- parallelism probes (2 cores; never oversubscribe) ---
    R["cpu_count"] = os.cpu_count()
    total_bytes = 8 << 20
    t0 = time.perf_counter()
    single = _mp_sha_chunk((total_bytes, 1))
    R["mp_sha_single_proc_MB_s"] = round(single, 1)
    with ProcessPoolExecutor(max_workers=2) as ex:
        parts = list(ex.map(_mp_sha_chunk, [(total_bytes // 2, 2), (total_bytes // 2, 3)]))
    R["mp_sha_2proc_MB_s_each"] = [round(x, 1) for x in parts]
    R["mp_sha_2proc_total_MB_s"] = round(sum(parts), 1)
    R["parallel_speedup_sha"] = round(sum(parts) / single, 2)

    with open(os.path.join(WB, "results", "benchmarks_python.json"), "w") as f:
        json.dump(R, f, indent=1, default=str)
    print(json.dumps(R, indent=1, default=str))

if __name__ == "__main__":
    main()
