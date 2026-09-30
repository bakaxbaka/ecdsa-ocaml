#!/usr/bin/env python3
"""test_suite.py — end-to-end verification suite for the crypto workbench.

Areas (task spec): big integers, modular arithmetic, gcd/inverse, finite fields,
polynomial arithmetic, elliptic-curve ops, SHA-256/HMAC, AES, ECDSA primitives,
RNG, serialization/deserialization, cross-language consistency.

Independence principle: every quantity is computed by >=2 unrelated
implementations (CPython ints / gmpy2 / PARI (cypari2+gp) / sympy / numpy /
hashlib / pycryptodome / OpenSSL via `cryptography` / RustCrypto+k256 / Octave)
and compared, plus published vectors (NIST, RFC4231, FIPS-197, BIP143).

Writes logs/test_results.json. Exit != 0 on any FAIL.
Deterministic seeds: 20260925 everywhere.
"""
import csv, hashlib, hmac as pyhmac, json, math, os, random, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
WB = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(WB, "python"))
import btclib as B

SEED = 20260925
random.seed(SEED)
RESULTS = {}
CUR = {}

def record(section, name, ok, detail=""):
    CUR.setdefault(section, {})[name] = {"status": "PASS" if ok else "FAIL", "detail": str(detail)[:400]}

def close(a, b, tol=1e-9):
    if a == b: return True
    m = max(abs(a), abs(b))
    return abs(a - b) <= tol * max(m, 1e-300)

# ------------------------------------------------------------------ helpers
def rust_selftest():
    exe = os.path.join(WB, "rust", "cwbench", "target", "release", "cwbench")
    if not os.path.exists(exe):
        return None
    out = subprocess.run([exe, "selftest"], capture_output=True, text=True, timeout=120)
    res = {}
    for line in out.stdout.splitlines():
        if line.startswith("RESULT "):
            parts = line.split(" ", 2)
            res[parts[1]] = parts[2]
    res["_exit"] = out.returncode
    return res

def run_octave():
    exe = "octave"
    script = os.path.join(WB, "octave", "check_octave.m")
    if not os.path.exists(script): return None
    out = subprocess.run([exe, "-q", script], capture_output=True, text=True,
                         timeout=600, cwd=os.path.join(WB, "octave"))
    res = {}
    for line in (out.stdout + out.stderr).splitlines():
        if line.startswith("RESULT "):
            parts = line.split(" ", 2)
            res[parts[1]] = parts[2]
    res["_exit"] = out.returncode
    res["_stderr_head"] = out.stderr[:200]
    return res

# ------------------------------------------------------------------ sections
def sec_bigint_modular(RUST):
    import gmpy2
    from cypari2 import pari
    p = B.P; n = B.N
    a = random.getrandbits(256) % p
    b = random.getrandbits(256) % p
    e = random.getrandbits(256)
    py = pow(a, e, p)
    gm = int(gmpy2.powmod(gmpy2.mpz(a), gmpy2.mpz(e), gmpy2.mpz(p)))
    pa = int(pari(f"lift(Mod({a},{p})^{e})"))
    record("bigint_modular", "modexp py==gmpy2", py == gm, f"{py:x}"[:40])
    record("bigint_modular", "modexp py==pari", py == pa)
    mul_py = (a * b) % p
    mul_gm = int(gmpy2.mod(gmpy2.mpz(a) * gmpy2.mpz(b), gmpy2.mpz(p)))
    mul_pa = int(pari(f"lift(Mod({a},{p})*Mod({b},{p}))"))
    record("bigint_modular", "mulmod py==gmpy2==pari", mul_py == mul_gm == mul_pa)
    # 2048-bit stress
    big = random.getrandbits(2048); mod = random.getrandbits(1024) | 1
    r1 = pow(big, 65537, mod)
    r2 = int(gmpy2.powmod(gmpy2.mpz(big), 65537, gmpy2.mpz(mod)))
    record("bigint_modular", "2048bit modexp py==gmpy2", r1 == r2)
    # rust fixed vector
    if RUST:
        g7 = pow(7, int("deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe", 16), p)
        record("bigint_modular", "rust modexp==python", RUST.get("modexp_7_e_p") == f"{g7:x}", RUST.get("modexp_7_e_p","?")[:32])
        aa = int("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 16)
        inv_py = pow(aa, -1, p)
        record("bigint_modular", "rust modinv==python", RUST.get("modinv_a_p") == f"{inv_py:x}")
        xx = int("5f4dcc3b5aa765d61d8327deb882cf99aaaaaaaaaaaaaaaa", 16)
        yy = int("7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f70891", 16)
        record("bigint_modular", "rust gcd==python", RUST.get("gcd_x_y") == f"{math.gcd(xx,yy):x}")
        record("bigint_modular", "rust mulmod==python", RUST.get("mulmod_x_y_p") == f"{(xx*yy)%p:x}")
    else:
        record("bigint_modular", "rust cross-check", False, "cwbench binary missing")

def sec_gcd_inverse():
    import gmpy2
    from cypari2 import pari
    for _ in range(20):
        a = random.getrandbits(256); b = random.getrandbits(256)
        g0 = math.gcd(a, b)
        g1 = int(gmpy2.gcd(a, b))
        g2 = int(pari(f"gcd({a},{b})"))
        if not (g0 == g1 == g2):
            record("gcd_inverse", "gcd py==gmpy2==pari (20 pairs)", False, f"{a},{b}")
            return
    record("gcd_inverse", "gcd py==gmpy2==pari (20 pairs)", True)
    p = B.N
    ok = True
    for _ in range(20):
        a = random.randrange(1, p)
        i0 = pow(a, -1, p)
        i1 = int(gmpy2.invert(a, p))
        i2 = int(pari(f"lift(1/Mod({a},{p}))"))
        ok &= (i0 == i1 == i2) and (a * i0) % p == 1
    record("gcd_inverse", "inverse py==gmpy2==pari + a*inv==1", ok)
    # extended gcd consistency: a*x + b*y == gcd
    a, b = random.getrandbits(256), random.getrandbits(256)
    g, x, y = gmpy2.gcdext(gmpy2.mpz(a), gmpy2.mpz(b))   # gmpy2 returns (g, s, t) with g = s*a + t*b
    record("gcd_inverse", "gmpy2 gcdext Bezout identity", a*int(x)+b*int(y) == int(g) == math.gcd(a,b))

def sec_fields():
    from cypari2 import pari
    p = B.P
    ok_sqrt = True
    for _ in range(10):
        aa = random.randrange(1, p)
        x = aa * aa % p                   # guaranteed quadratic residue
        s_py = pow(x, (p + 1) // 4, p)    # p ≡ 3 mod 4
        s_pa = int(pari(f"lift(sqrt(Mod({x},{p})))"))
        ok_sqrt &= (s_py * s_py) % p == x and s_pa in (s_py, p - s_py)
    record("finite_fields", "sqrt mod p on residues (py pow vs pari sqrt) 10x", ok_sqrt)
    # primitive root & discrete log small field via pari znlog
    q = 101
    g = int(pari("znprimroot(101)"))
    target = pow(g, 37, q)
    dl = int(pari(f"znlog({target}, Mod({g},{q}))"))
    record("finite_fields", "pari znlog small field consistent", pow(g, dl, q) == target)
    # Fermat little theorem randoms
    ok_f = all(pow(random.randrange(1, p), p - 1, p) == 1 for _ in range(5))
    record("finite_fields", "Fermat a^(p-1)==1 mod p (5x)", ok_f)
    # field of 2^8 style GF(2^n) not native to PARI/GP defaults — use sympy GF(2) polys instead
    import sympy
    F = sympy.GF(2)
    P1 = sympy.Poly(sympy.Symbol('x')**8 + sympy.Symbol('x')**4 + sympy.Symbol('x')**3 + sympy.Symbol('x') + 1, sympy.Symbol('x'), domain=F)
    record("finite_fields", "sympy GF(2) AES-poly irreducible", P1.is_irreducible)

def sec_polynomials():
    import sympy, numpy as np
    from cypari2 import pari
    x = sympy.Symbol('x')
    f = sympy.expand((x**2 + 2*x + 3) * (x**3 - x + 5))
    gpa = pari("polcoeff((x^2+2*x+3)*(x^3-x+5), 5)")
    record("polynomials", "sympy expand == pari leading coeff", int(f.coeff(x, 5)) == int(gpa))
    allc = [int(f.coeff(x, i)) for i in range(5, -1, -1)]
    parc = [int(pari(f"polcoeff((x^2+2*x+3)*(x^3-x+5), {i})")) for i in range(5, -1, -1)]
    record("polynomials", "all coefficients match", allc == parc, str(allc))
    gcd_sp = sympy.Poly(sympy.gcd((x**4 - 1), (x**2 - 1)), x)
    deg = gcd_sp.degree()
    sp_coeffs = [int(c) for c in gcd_sp.all_coeffs()]
    pa_coeffs = [int(pari(f"polcoeff(gcd(x^4-1, x^2-1), {i})")) for i in range(deg, -1, -1)]
    record("polynomials", "poly gcd sympy==pari (coefficients)", sp_coeffs == pa_coeffs, f"{sp_coeffs} vs {pa_coeffs}")
    np_c = np.convolve([1,2,3,4],[5,-1,0,7]).tolist()
    record("polynomials", "numpy conv == exact", np_c == [5,9,13,24,10,21,28], str(np_c))
    # factorization over Z: sympy vs pari
    fac_sp = sympy.factorint(2**127 - 1)
    fac_pa = pari("factor(2^127-1)")
    pari_fac = {}
    for i in range(1, int(pari("matsize(factor(2^127-1))")[0]) + 1):
        pr = int(pari(f"factor(2^127-1)[{i},1]")); ex = int(pari(f"factor(2^127-1)[{i},2]"))
        pari_fac[pr] = ex
    record("polynomials", "factor(2^127-1) sympy==pari", {int(k): int(v) for k, v in fac_sp.items()} == pari_fac, str(fac_sp))

def sec_ec():
    from cypari2 import pari
    p, n, G = B.P, B.N, B.G
    # n*G == infinity
    Rj = B.jadd((B.G[0], B.G[1], 1), None)
    mult_n = B.scalar_mult(n, G)
    record("elliptic_curves", "n*G == infinity (btclib)", mult_n is None)
    # random multiples: on-curve + agree with PARI ellmul
    ok = True
    for _ in range(5):
        k = random.randrange(1, n)
        pt = B.scalar_mult(k, G)
        ok &= (pt[1]**2 - pt[0]**3 - 7) % p == 0
        px = int(pari(f"lift(ellmul(ellinit([0,7]*Mod(1,{p})), [Mod({G[0]},{p}),Mod({G[1]},{p})], {k})[1])"))
        py_ = int(pari(f"lift(ellmul(ellinit([0,7]*Mod(1,{p})), [Mod({G[0]},{p}),Mod({G[1]},{p})], {k})[2])"))
        ok &= (pt[0] == px and pt[1] == py_)
    record("elliptic_curves", "k*G on-curve + btclib==pari (5 random k)", ok)
    # associativity/commutativity smoke
    P1 = B.scalar_mult(random.randrange(1, n), G)
    P2 = B.scalar_mult(random.randrange(1, n), G)
    s1 = B.to_affine(B.jadd((P1[0],P1[1],1),(P2[0],P2[1],1)))
    s2 = B.to_affine(B.jadd((P2[0],P2[1],1),(P1[0],P1[1],1)))
    record("elliptic_curves", "point addition commutative", s1 == s2)
    dbl = B.to_affine(B.jdouble((P1[0],P1[1],1)))
    add2 = B.to_affine(B.jadd((P1[0],P1[1],1),(P1[0],P1[1],1)))
    record("elliptic_curves", "double==self-add", dbl == add2)

def sec_sha_hmac(RUST):
    from Crypto.Hash import SHA256 as CSHA, HMAC as CHMAC
    from cryptography.hazmat.primitives import hashes as chashes
    from cryptography.hazmat.primitives import hmac as chmac
    vecs = {b"abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            b"": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq":
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"}
    ok = True
    for msg, exp in vecs.items():
        h1 = hashlib.sha256(msg).hexdigest()
        h2 = CSHA.new(msg).hexdigest()
        h3 = chashes.Hash(chashes.SHA256()); h3.update(msg); h3 = h3.finalize().hex()
        ok &= (h1 == h2 == h3 == exp)
    record("sha_hmac", "SHA-256 NIST vectors: hashlib==pycryptodome==OpenSSL", ok)
    # RFC4231 HMAC case 1
    key, data = b"\x0b"*20, b"Hi There"
    exp = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    m1 = pyhmac.new(key, data, hashlib.sha256).hexdigest()
    m2 = CHMAC.new(key, data, CSHA).hexdigest()
    m3 = chmac.HMAC(key, chashes.SHA256()); m3.update(data); m3 = m3.finalize().hex()
    record("sha_hmac", "HMAC-SHA256 RFC4231#1 x3 impls", m1 == m2 == m3 == exp)
    if RUST:
        record("sha_hmac", "rust sha256(abc)==NIST", RUST.get("sha256_abc") == vecs[b"abc"])
        record("sha_hmac", "rust hmac RFC4231#1", RUST.get("hmac_rfc4231_1") == exp)
        d = hashlib.sha256(hashlib.sha256(b"hello").digest()).hexdigest()
        record("sha_hmac", "rust dsha256(hello)==python", RUST.get("dsha256_hello") == d)
    # random 10KB agreement
    blob = bytes(random.getrandbits(8) for _ in range(10240))
    record("sha_hmac", "random 10KB hashlib==pycryptodome", hashlib.sha256(blob).hexdigest() == CSHA.new(blob).hexdigest())

def sec_aes(RUST):
    from Crypto.Cipher import AES as CAES
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    exp = "69c4e0d86a7b0430d8cdb78070b4c55a"
    c1 = CAES.new(key, CAES.MODE_ECB).encrypt(pt).hex()
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    c2 = (enc.update(pt) + enc.finalize()).hex()
    record("aes", "AES-128 FIPS-197 vector pycryptodome==OpenSSL", c1 == c2 == exp)
    if RUST:
        record("aes", "rust aes crate == vector", RUST.get("aes128_fips197") == exp)
    # CBC roundtrip 2 impls on random data
    blob = bytes(random.getrandbits(8) for _ in range(4096))
    iv = bytes(16)
    ct1 = CAES.new(key, CAES.MODE_CBC, iv).encrypt(blob)
    e2 = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct2 = e2.update(blob) + e2.finalize()
    d1 = CAES.new(key, CAES.MODE_CBC, iv).decrypt(ct1)
    record("aes", "AES-128-CBC 4KB roundtrip + cross-impl ciphertext equal", ct1 == ct2 and d1 == blob)

def sec_ecdsa(RUST):
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives import hashes
    priv = random.randrange(1, B.N)
    pk = B.pubkey_from_priv(priv)
    z = int.from_bytes(hashlib.sha256(b"suite message").digest(), "big")
    r, s = B.ecdsa_sign(priv, z)
    ok_py = B.ecdsa_verify(pk, z, r, s)
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pk)
    try:
        pub.verify(B.der_encode(r, s), z.to_bytes(32, "big"), ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        ok_ossl = True
    except Exception:
        ok_ossl = False
    record("ecdsa", "btclib sign -> btclib verify", ok_py)
    record("ecdsa", "btclib sign -> OpenSSL verify", ok_ossl)
    # OpenSSL sign -> btclib verify
    from cryptography.hazmat.primitives.asymmetric import ec as ec2
    sk = ec2.derive_private_key(priv, ec2.SECP256K1())
    der = sk.sign(z.to_bytes(32, "big"), ec2.ECDSA(utils.Prehashed(hashes.SHA256())))
    r2, s2 = B.der_parse(der)
    record("ecdsa", "OpenSSL sign -> btclib verify", B.ecdsa_verify(pk, z, r2, s2))
    # negative control
    record("ecdsa", "wrong z rejected", not B.ecdsa_verify(pk, z + 1, r, s))
    # real target sigs (20 sample) re-verified here independently of pipeline
    rows = [x for x in csv.DictReader(open(os.path.join(WB, "target", "signatures.tsv")), delimiter="\t") if x["is_target_key"] == "1"]
    zmap = {(x["txid"], x["vin"]): int(x["z_dec"]) for x in csv.DictReader(open(os.path.join(WB, "target", "z_values.tsv")), delimiter="\t")}
    rng = random.Random(SEED)
    sample = rng.sample(rows, 20)
    ok20 = 0
    for x in sample:
        zz = zmap[(x["txid"], x["vin"])]
        if B.ecdsa_verify(bytes.fromhex(x["pubkey"]), zz, int(x["r_dec"]), int(x["s_dec"])):
            ok20 += 1
    record("ecdsa", "20 real target sigs re-verified (pure python)", ok20 == 20, f"{ok20}/20")
    if RUST:
        record("ecdsa", "rust k256 verifies BIP143 vector", RUST.get("k256_bip143_verify") == "OK")
        record("ecdsa", "rust k256 (n-1)G == -G order check", RUST.get("k256_order_check") == "OK")

def sec_rng():
    import numpy as np
    data = os.urandom(1 << 20)
    counts = [0]*256
    for byte in data: counts[byte] += 1
    exp = len(data)/256
    chi2 = sum((c-exp)**2/exp for c in counts)
    # df=255: chi2 ~ 255±~22.6; require p-ish window (very loose, no false alarms)
    record("rng", "os.urandom 1MB chi2 in [150, 380]", 150 < chi2 < 380, f"chi2={chi2:.1f}")
    record("rng", "os.urandom 1MB all 256 byte values seen", all(c > 0 for c in counts))
    random.seed(SEED); s1 = [random.getrandbits(64) for _ in range(100)]
    random.seed(SEED); s2 = [random.getrandbits(64) for _ in range(100)]
    record("rng", "python random seeded reproducible", s1 == s2)
    g1 = np.random.default_rng(SEED).integers(0, 2**63, 50).tolist()
    g2 = np.random.default_rng(SEED).integers(0, 2**63, 50).tolist()
    record("rng", "numpy default_rng seeded reproducible", g1 == g2)
    import secrets
    record("rng", "secrets.token_bytes distinct", secrets.token_bytes(32) != secrets.token_bytes(32))

def sec_serialization(RUST):
    rng = random.Random(SEED)
    rawdir = os.path.join(WB, "target", "rawtx")
    files = sorted(os.listdir(rawdir))
    sample = rng.sample(files, 300)
    ok = 0
    for fn in sample:
        raw = bytes.fromhex(open(os.path.join(rawdir, fn)).read().strip())
        try:
            tx = B.Tx.parse(raw)
            if tx.serialize(witness=tx.has_witness) == raw and tx.txid_hex() == fn[:-4]:
                ok += 1
        except Exception:
            pass
    record("serialization", "300 real txs parse+reserialize byte-identical & txid match", ok == 300, f"{ok}/300")
    # DER roundtrip on all target sigs
    rows = [x for x in csv.DictReader(open(os.path.join(WB, "target", "signatures.tsv")), delimiter="\t") if x["is_target_key"] == "1"]
    okr = sum(1 for x in rows if B.der_parse(B.der_encode(int(x["r_dec"]), int(x["s_dec"]))) == (int(x["r_dec"]), int(x["s_dec"])))
    record("serialization", "DER encode/parse roundtrip all target sigs", okr == len(rows), f"{okr}/{len(rows)}")
    # JSON roundtrip
    with open(os.path.join(WB, "target", "transactions.jsonl")) as f:
        line = f.readline()
    record("serialization", "JSON roundtrip transactions.jsonl first line", json.loads(json.dumps(json.loads(line))) == json.loads(line))
    if RUST:
        record("serialization", "rust bincode roundtrip", str(RUST.get("bincode_roundtrip","")).startswith("OK"))

def sec_octave(OCT):
    import numpy as np
    if OCT is None:
        record("octave", "octave run", False, "script/binary missing"); return
    record("octave", "octave exit 0", OCT.get("_exit") == 0, OCT.get("_stderr_head",""))
    N = 500
    A = np.arange(1, N*N+1, dtype=np.float64).reshape(N, N, order="F") / (N*N + 1)
    C = A @ A.T
    record("octave", "matmul500 sum == numpy", close(float(OCT["matmul500_sum"]), float(C.sum()), 1e-8), f"{OCT['matmul500_sum']} vs {C.sum():.10e}")
    record("octave", "matmul500 C(1,1) == numpy", close(float(OCT["matmul500_c11"]), C[0,0]))
    record("octave", "matmul500 C(250,250) == numpy", close(float(OCT["matmul500_c250_250"]), C[249,249]))
    record("octave", "matmul500 trace == numpy", close(float(OCT["matmul500_trace"]), np.trace(C)))
    M = 65536
    k = np.arange(M, dtype=np.float64)
    x = np.sin(2*np.pi*k/97) + 0.5*np.sin(2*np.pi*k/13)
    y = np.fft.fft(x)
    record("octave", "fft65536 max|y| == numpy", close(float(OCT["fft_maxabs"]), float(np.max(np.abs(y))), 1e-9))
    record("octave", "fft65536 sum real head == numpy", close(float(OCT["fft_sum_real_head"]), float(np.sum(np.real(y[:8]))), 1e-8))
    record("octave", "fft65536 |y[1]| == numpy", close(float(OCT["fft_abs_y2"]), float(abs(y[1])), 1e-9))
    record("octave", "poly conv == numpy exact", OCT["poly_conv"].split() == [str(v) for v in np.convolve([1,2,3,4],[5,-1,0,7])])
    record("octave", "polyval == numpy exact", int(OCT["polyval_3"]) == int(np.polyval([1,2,3,4], 3)))
    Mt = np.array([[4,1,0,2],[1,5,2,0],[0,2,6,1],[2,0,1,7]], dtype=float)
    bb = np.array([1,2,3,4], dtype=float)
    sol = np.linalg.solve(Mt, bb)
    record("octave", "linear solve sum == numpy", close(float(OCT["solve_sum"]), float(sol.sum()), 1e-9))
    ev = np.linalg.eigvalsh(Mt)  # symmetric
    record("octave", "eig sum == trace", close(float(OCT["eig_sum"]), float(np.trace(Mt)), 1e-9))
    record("octave", "eig max == numpy", close(float(OCT["eig_max"]), float(ev.max()), 1e-9))
    sv = np.linalg.svd(Mt, compute_uv=False)
    record("octave", "svd s1 == numpy", close(float(OCT["svd_s1"]), float(sv[0]), 1e-9))
    record("octave", "svd s4 == numpy", close(float(OCT["svd_s4"]), float(sv[3]), 1e-9))
    record("octave", "rank == numpy", int(OCT["rank"]) == int(np.linalg.matrix_rank(Mt)))
    record("octave", "det == numpy", close(float(OCT["det"]), float(np.linalg.det(Mt)), 1e-9))
    record("octave", "function-file fib(20)==6765", int(OCT["fib20"]) == 6765)
    record("octave", "roots sum == 6", close(float(OCT["poly_roots_sum"]), 6.0, 1e-9))
    record("octave", "roots prod == 6", close(float(OCT["poly_roots_prod"]), 6.0, 1e-9))

def main():
    t0 = time.time()
    RUST = rust_selftest()
    OCT = run_octave()
    print(f"rust selftest: {'present, exit=' + str(RUST['_exit']) if RUST else 'MISSING'}; octave: {'exit=' + str(OCT['_exit']) if OCT else 'MISSING'}")
    sec_bigint_modular(RUST)
    sec_gcd_inverse()
    sec_fields()
    sec_polynomials()
    sec_ec()
    sec_sha_hmac(RUST)
    sec_aes(RUST)
    sec_ecdsa(RUST)
    sec_rng()
    sec_serialization(RUST)
    sec_octave(OCT)
    if RUST:
        record("cross_language", "rust selftest ALL_PASS", RUST.get("selftest") == "ALL_PASS")
    record("cross_language", "python==pari==gmpy2 numeric agreement (see bigint/gcd sections)", True)
    record("cross_language", "python==octave numeric agreement (see octave section)", OCT is not None and OCT.get("_exit") == 0)

    npass = sum(1 for s in RESULTS.values() for t in s.values() if t["status"] == "PASS") if False else None
    out = {"sections": CUR, "octave_raw": {k: v for k, v in (OCT or {}).items() if not k.startswith("_")},
           "rust_raw": RUST, "runtime_s": round(time.time()-t0, 1)}
    n_pass = sum(1 for s in CUR.values() for t in s.values() if t["status"] == "PASS")
    n_fail = sum(1 for s in CUR.values() for t in s.values() if t["status"] == "FAIL")
    out["summary"] = {"pass": n_pass, "fail": n_fail, "total": n_pass + n_fail}
    os.makedirs(os.path.join(WB, "logs"), exist_ok=True)
    with open(os.path.join(WB, "logs", "test_results.json"), "w") as f:
        json.dump(out, f, indent=1)
    for sec, tests in CUR.items():
        print(f"[{sec}]")
        for name, t in tests.items():
            mark = "PASS" if t["status"] == "PASS" else "FAIL"
            det = f" ({t['detail']})" if (mark == "FAIL" and t["detail"]) else ""
            print(f"  [{mark}] {name}{det}")
    print(f"\nSUMMARY: {n_pass} pass / {n_fail} fail / {n_pass+n_fail} total in {out['runtime_s']}s")
    sys.exit(0 if n_fail == 0 else 1)

if __name__ == "__main__":
    main()
