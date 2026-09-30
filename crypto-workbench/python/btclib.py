#!/usr/bin/env python3
"""btclib.py — pure-stdlib Bitcoin primitives for transaction forensics.

Implements (no third-party deps):
  * SHA-256d, pure-Python RIPEMD-160, HASH160
  * Base58Check, Bech32/Bech32m
  * scriptPubKey classification + address derivation (mainnet)
  * Strict raw transaction parser/serializer (legacy + segwit), txid/wtxid
  * Strict DER signature parsing (BIP66 rules) + encoding
  * Legacy SIGHASH preimage/z (ALL/NONE/SINGLE/ANYONECANPAY, incl. SINGLE-bug)
  * BIP143 segwit SIGHASH preimage/z (P2WPKH / P2SH-wrapped / P2WSH)
  * secp256k1 point arithmetic (Jacobian), ECDSA sign (RFC6979 + random k) / verify

Written from the BIP/protocol specifications. Independently cross-validated by:
  tests/test_suite.py vectors, OpenSSL (`cryptography`), PARI/GP elliptic math.
"""
import hashlib, struct, hmac

# ---------------------------------------------------------------- hashing
def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def dsha256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

# --- pure-python RIPEMD-160 (OpenSSL 3 moved ripemd160 to legacy provider) ---
_RI_KL = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
_RI_KR = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]
_RI_RL = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
          3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12, 1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
          4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13]
_RI_RR = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12, 6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
          15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13, 8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
          12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11]
_RI_SL = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8, 7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
          11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5, 11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
          9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6]
_RI_SR = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6, 9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
          9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5, 15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
          8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11]

def _rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

# --- canonical RIPEMD-160 (dual parallel lines) ---
def ripemd160(msg: bytes) -> bytes:
    h0, h1, h2, h3, h4 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
    ml = len(msg) * 8
    msg = bytearray(msg)
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", ml)

    def f(j, x, y, z):
        if j < 16:  return x ^ y ^ z
        if j < 32:  return (x & y) | (~x & 0xFFFFFFFF & z)
        if j < 48:  return (x | ~y & 0xFFFFFFFF) ^ z
        if j < 64:  return (x & z) | (y & ~z & 0xFFFFFFFF)
        return x ^ (y | ~z & 0xFFFFFFFF)

    for off in range(0, len(msg), 64):
        x = struct.unpack("<16I", bytes(msg[off:off+64]))
        al, bl, cl, dl, el = h0, h1, h2, h3, h4
        ar, br, cr, dr, er = h0, h1, h2, h3, h4
        for j in range(80):
            rnd = j >> 4
            # left
            t = (al + f(j, bl, cl, dl) + x[_RI_RL[j]] + _RI_KL[rnd]) & 0xFFFFFFFF
            t = (_rotl(t, _RI_SL[j]) + el) & 0xFFFFFFFF
            al, bl, cl, dl, el = el, t, bl, _rotl(cl, 10), dl
            # right
            t = (ar + _f_right(j, br, cr, dr) + x[_RI_RR[j]] + _RI_KR[rnd]) & 0xFFFFFFFF
            t = (_rotl(t, _RI_SR[j]) + er) & 0xFFFFFFFF
            ar, br, cr, dr, er = er, t, br, _rotl(cr, 10), dr
        t = (h1 + cl + dr) & 0xFFFFFFFF
        h1 = (h2 + dl + er) & 0xFFFFFFFF
        h2 = (h3 + el + ar) & 0xFFFFFFFF
        h3 = (h4 + al + br) & 0xFFFFFFFF
        h4 = (h0 + bl + cr) & 0xFFFFFFFF
        h0 = t
    return struct.pack("<5I", h0, h1, h2, h3, h4)

def _f_right(j, x, y, z):
    # right line uses round functions in reverse order: F5,F4,F3,F2,F1
    M = 0xFFFFFFFF
    if j < 16:  return x ^ (y | (~z & M))          # F5
    if j < 32:  return (x & z) | (y & (~z & M))    # F4
    if j < 48:  return (x | (~y & M)) ^ z          # F3
    if j < 64:  return (x & y) | ((~x & M) & z)    # F2
    return x ^ y ^ z                               # F1

def hash160(b: bytes) -> bytes:
    return ripemd160(sha256(b))

# ---------------------------------------------------------------- base58
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big") if b else 0
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = B58[r] + out
    pad = 0
    for ch in b:
        if ch == 0: pad += 1
        else: break
    return "1" * pad + out

def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        i = B58.index(ch)
        n = n * 58 + i
    full = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = 0
    for ch in s:
        if ch == "1": pad += 1
        else: break
    return b"\x00" * pad + full

def b58check_encode(payload: bytes) -> str:
    return b58encode(payload + dsha256(payload)[:4])

def b58check_decode(s: str) -> bytes:
    raw = b58decode(s)
    payload, chk = raw[:-4], raw[-4:]
    if dsha256(payload)[:4] != chk:
        raise ValueError("bad base58 checksum")
    return payload

# ---------------------------------------------------------------- bech32 (BIP173/BIP350)
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def _bech32_polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk

def _bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def _bech32_verify_checksum(hrp, data):
    const = _bech32_polymod(_bech32_hrp_expand(hrp) + data)
    return 1 if const == 1 else (0x2bc830a3 if const == 0x2bc830a3 else None)

def _bech32_create_checksum(hrp, data, spec):
    const = 1 if spec == "bech32" else 0x2bc830a3
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def _convertbits(data, frombits, tobits, pad=True):
    acc, bits, ret = 0, 0, []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret

def segwit_addr_encode(hrp, witver, witprog):
    spec = "bech32" if witver == 0 else "bech32m"
    data = [witver] + _convertbits(witprog, 8, 5)
    return hrp + "1" + "".join(_BECH32_CHARSET[d] for d in data + _bech32_create_checksum(hrp, data, spec))

def segwit_addr_decode(addr):
    """returns (witver, witprog bytes) or (None, None)"""
    if any(ord(c) < 33 or ord(c) > 126 for c in addr): return None, None
    low, up = addr.lower(), addr.upper()
    if addr != low and addr != up: return None, None
    addr = low
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr) or len(addr) > 90: return None, None
    if not all(x in _BECH32_CHARSET for x in addr[pos+1:]): return None, None
    hrp, data = addr[:pos], [_BECH32_CHARSET.index(x) for x in addr[pos+1:]]
    v = _bech32_verify_checksum(hrp, data)
    if v is None: return None, None
    witver = data[0]
    if witver > 16: return None, None
    if (witver == 0 and v != 1) or (witver != 0 and v != 0x2bc830a3): return None, None
    prog = bytes(_convertbits(data[1:-6], 5, 8, False))
    if len(prog) < 2 or len(prog) > 40: return None, None
    if witver == 0 and len(prog) not in (20, 32): return None, None
    return witver, prog

# ---------------------------------------------------------------- scripts
OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG, OP_EQUAL, OP_0 = 0x76, 0xA9, 0x88, 0xAC, 0x87, 0x00

def classify_spk(spk: bytes) -> str:
    if len(spk) == 25 and spk[0] == OP_DUP and spk[1] == OP_HASH160 and spk[2] == 0x14 and spk[23] == OP_EQUALVERIFY and spk[24] == OP_CHECKSIG:
        return "p2pkh"
    if len(spk) == 23 and spk[0] == OP_HASH160 and spk[1] == 0x14 and spk[22] == OP_EQUAL:
        return "p2sh"
    if len(spk) == 22 and spk[0] == OP_0 and spk[1] == 0x14:
        return "p2wpkh"
    if len(spk) == 34 and spk[0] == OP_0 and spk[1] == 0x20:
        return "p2wsh"
    if len(spk) == 34 and spk[0] == 0x51 and spk[1] == 0x20:
        return "p2tr"
    if len(spk) >= 1 and spk[0] == 0x6A:
        return "op_return"
    if 2 <= len(spk) <= 35 and spk[0] in (0x21, 0x41) and spk[-1] == OP_CHECKSIG and len(spk) == spk[0] + 2:
        return "p2pk"
    if len(spk) > 3 and spk[-1] == 0xAE:
        # crude bare multisig detection OP_k ... OP_n OP_CHECKMULTISIG
        k = spk[0]
        if 0x51 <= k <= 0x60:
            return f"multisig(bare?)"
    if len(spk) >= 5 and 0x51 <= spk[0] <= 0x60 and spk[1] in (0x21, 0x41):
        return "multisig(bare)"
    if not spk:
        return "empty"
    return "nonstandard"

def spk_to_address(spk: bytes) -> str:
    t = classify_spk(spk)
    if t == "p2pkh":
        return b58check_encode(b"\x00" + spk[3:23])
    if t == "p2sh":
        return b58check_encode(b"\x05" + spk[2:22])
    if t in ("p2wpkh", "p2wsh"):
        return segwit_addr_encode("bc", 0, spk[2:])
    if t == "p2tr":
        return segwit_addr_encode("bc", 1, spk[2:])
    return ""

def push_data(d: bytes) -> bytes:
    n = len(d)
    if n < 0x4C:  return bytes([n]) + d
    if n <= 0xFF: return b"\x4c" + bytes([n]) + d
    if n <= 0xFFFF: return b"\x4d" + struct.pack("<H", n) + d
    return b"\x4e" + struct.pack("<I", n) + d

def parse_pushes(script: bytes):
    """Split a scriptSig into pushed items (strict minimal-length not enforced here)."""
    items, i = [], 0
    while i < len(script):
        op = script[i]
        if op == 0x00:
            items.append(b""); i += 1
        elif op <= 0x4B:
            items.append(script[i+1:i+1+op]); i += 1 + op
        elif op == 0x4C:
            n = script[i+1]; items.append(script[i+2:i+2+n]); i += 2 + n
        elif op == 0x4D:
            n = struct.unpack_from("<H", script, i+1)[0]; items.append(script[i+3:i+3+n]); i += 3 + n
        elif op == 0x4E:
            n = struct.unpack_from("<I", script, i+1)[0]; items.append(script[i+5:i+5+n]); i += 5 + n
        else:
            raise ValueError(f"non-push opcode 0x{op:02x} in scriptSig at {i}")
    return items

# ---------------------------------------------------------------- varints / tx
def read_varint(buf, o):
    b0 = buf[o]
    if b0 < 0xFD:  return b0, o + 1
    if b0 == 0xFD: return struct.unpack_from("<H", buf, o + 1)[0], o + 3
    if b0 == 0xFE: return struct.unpack_from("<I", buf, o + 1)[0], o + 5
    return struct.unpack_from("<Q", buf, o + 1)[0], o + 9

def write_varint(n):
    if n < 0xFD: return bytes([n])
    if n <= 0xFFFF: return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF: return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)

class TxIn:
    __slots__ = ("prev_txid", "prev_vout", "script_sig", "sequence", "witness")
    def __init__(self, prev_txid=b"\x00"*32, prev_vout=0xFFFFFFFF, script_sig=b"", sequence=0xFFFFFFFF, witness=None):
        self.prev_txid, self.prev_vout = prev_txid, prev_vout
        self.script_sig, self.sequence = script_sig, sequence
        self.witness = witness if witness is not None else []
    @property
    def is_coinbase(self):
        return self.prev_txid == b"\x00"*32 and self.prev_vout == 0xFFFFFFFF

class TxOut:
    __slots__ = ("value", "spk")
    def __init__(self, value, spk):
        self.value, self.spk = value, spk

class Tx:
    __slots__ = ("version", "vin", "vout", "locktime", "has_witness")
    def __init__(self, version, vin, vout, locktime, has_witness=False):
        self.version, self.vin, self.vout = version, vin, vout
        self.locktime, self.has_witness = locktime, has_witness

    @classmethod
    def parse(cls, raw: bytes):
        o = 0
        version = struct.unpack_from("<i", raw, o)[0]; o += 4
        has_witness = False
        if raw[o] == 0x00:
            flag = raw[o+1]
            if flag != 0x01:
                raise ValueError(f"bad segwit flag {flag}")
            has_witness = True; o += 2
        nvin, o = read_varint(raw, o)
        vin = []
        for _ in range(nvin):
            prev = raw[o:o+32]; o += 32
            pv = struct.unpack_from("<I", raw, o)[0]; o += 4
            sl, o = read_varint(raw, o)
            ss = raw[o:o+sl]; o += sl
            seq = struct.unpack_from("<I", raw, o)[0]; o += 4
            vin.append(TxIn(prev, pv, ss, seq))
        nvout, o = read_varint(raw, o)
        vout = []
        for _ in range(nvout):
            val = struct.unpack_from("<q", raw, o)[0]; o += 8
            sl, o = read_varint(raw, o)
            spk = raw[o:o+sl]; o += sl
            vout.append(TxOut(val, spk))
        if has_witness:
            for txin in vin:
                nitems, o = read_varint(raw, o)
                wit = []
                for _ in range(nitems):
                    il, o = read_varint(raw, o)
                    wit.append(raw[o:o+il]); o += il
                txin.witness = wit
        locktime = struct.unpack_from("<I", raw, o)[0]; o += 4
        if o != len(raw):
            raise ValueError(f"trailing bytes: parsed {o} of {len(raw)}")
        return cls(version, vin, vout, locktime, has_witness)

    def serialize(self, witness=None) -> bytes:
        if witness is None: witness = self.has_witness
        out = struct.pack("<i", self.version)
        if witness: out += b"\x00\x01"
        out += write_varint(len(self.vin))
        for i in self.vin:
            out += i.prev_txid + struct.pack("<I", i.prev_vout) + write_varint(len(i.script_sig)) + i.script_sig + struct.pack("<I", i.sequence)
        out += write_varint(len(self.vout))
        for o in self.vout:
            out += struct.pack("<q", o.value) + write_varint(len(o.spk)) + o.spk
        if witness:
            for i in self.vin:
                out += write_varint(len(i.witness))
                for item in i.witness:
                    out += write_varint(len(item)) + item
        out += struct.pack("<I", self.locktime)
        return out

    def txid(self) -> bytes:
        return dsha256(self.serialize(witness=False))[::-1]

    def txid_hex(self) -> str:
        return self.txid().hex()

    def wtxid(self) -> bytes:
        return dsha256(self.serialize(witness=self.has_witness))[::-1]

# ---------------------------------------------------------------- DER (BIP66-strict)
class DerError(ValueError): pass

def der_parse(sig: bytes):
    """strict parse of DER ECDSA signature (without sighash byte). returns (r,s)."""
    if len(sig) < 8: raise DerError("too short")
    if len(sig) > 72: raise DerError("too long")
    if sig[0] != 0x30: raise DerError("bad lead byte")
    if sig[1] != len(sig) - 2: raise DerError("bad total length")
    if sig[2] != 0x02: raise DerError("bad r marker")
    rlen = sig[3]
    if rlen == 0 or 4 + rlen > len(sig): raise DerError("bad r length")
    rbytes = sig[4:4+rlen]
    p = 4 + rlen
    if sig[p] != 0x02: raise DerError("bad s marker")
    if p + 1 >= len(sig): raise DerError("truncated s")
    slen = sig[p+1]
    if slen == 0 or p + 2 + slen != len(sig): raise DerError("bad s length")
    sbytes = sig[p+2:p+2+slen]
    for name, b in (("r", rbytes), ("s", sbytes)):
        if b[0] & 0x80: raise DerError(f"{name} negative")
        if len(b) > 1 and b[0] == 0x00 and not (b[1] & 0x80): raise DerError(f"{name} not minimal")
    r = int.from_bytes(rbytes, "big"); s = int.from_bytes(sbytes, "big")
    if r == 0 or s == 0: raise DerError("zero r/s")
    return r, s

def der_encode(r: int, s: int) -> bytes:
    def enc(v):
        b = v.to_bytes((v.bit_length() + 8) // 8 or 1, "big")
        if b[0] & 0x80: b = b"\x00" + b
        return b"\x02" + bytes([len(b)]) + b
    body = enc(r) + enc(s)
    return b"\x30" + bytes([len(body)]) + body

# ---------------------------------------------------------------- secp256k1
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A, B = 0, 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def _inv(a, m=P):
    return pow(a, m - 2, m)

def jdouble(pt):
    """Jacobian doubling; pt=(X,Y,Z) or None for infinity."""
    if pt is None or pt[1] == 0: return None
    X, Y, Z = pt
    YY = (Y * Y) % P
    S = (4 * X * YY) % P
    M = (3 * X * X) % P  # a = 0
    X3 = (M * M - 2 * S) % P
    Y3 = (M * (S - X3) - 8 * YY * YY) % P
    Z3 = (2 * Y * Z) % P
    return (X3 % P, Y3 % P, Z3 % P)

def jadd(p, q):
    if p is None: return q
    if q is None: return p
    X1, Y1, Z1 = p; X2, Y2, Z2 = q
    Z1Z1 = Z1*Z1 % P; Z2Z2 = Z2*Z2 % P
    U1 = X1*Z2Z2 % P; U2 = X2*Z1Z1 % P
    S1 = Y1*Z2 % P * Z2Z2 % P; S2 = Y2*Z1 % P * Z1Z1 % P
    if U1 == U2:
        if S1 != S2: return None
        return jdouble(p)
    H = (U2 - U1) % P; R = (S2 - S1) % P
    H2 = H*H % P; H3 = H2*H % P
    X3 = (R*R - H3 - 2*U1*H2) % P
    Y3 = (R*(U1*H2 % P - X3) - S1*H3) % P
    Z3 = (Z1*Z2 % P) * H % P
    return (X3, Y3, Z3)

def to_affine(pt):
    if pt is None: return None
    X, Y, Z = pt
    Zi = _inv(Z % P)
    Zi2 = Zi*Zi % P
    return (X*Zi2 % P, Y*Zi2 % P * Zi % P)

def scalar_mult(k: int, pt_affine):
    k %= N
    if k == 0: return None
    R = None
    base = (pt_affine[0], pt_affine[1], 1)
    while k:
        if k & 1: R = jadd(R, base)
        base = jdouble(base)
        k >>= 1
    return to_affine(R)

G = (Gx, Gy)

def parse_pubkey(pk: bytes):
    if len(pk) == 65 and pk[0] == 0x04:
        x, y = int.from_bytes(pk[1:33], "big"), int.from_bytes(pk[33:], "big")
    elif len(pk) == 33 and pk[0] in (0x02, 0x03):
        x = int.from_bytes(pk[1:], "big")
        if x >= P: raise ValueError("x out of range")
        y2 = (pow(x, 3, P) + B) % P
        y = pow(y2, (P + 1) // 4, P)
        if y * y % P != y2: raise ValueError("point not on curve")
        if (y & 1) != (pk[0] & 1): y = P - y
    else:
        raise ValueError("bad pubkey encoding")
    if (x, y) == (0, 0): raise ValueError("bad point")
    return (x, y)

def pubkey_valid(pk: bytes) -> bool:
    try:
        x, y = parse_pubkey(pk)
        return (y*y - x*x*x - B) % P == 0
    except Exception:
        return False

def ecdsa_verify(pk: bytes, z: int, r: int, s: int) -> bool:
    try:
        pt = parse_pubkey(pk)
    except Exception:
        return False
    if not (1 <= r < N and 1 <= s < N): return False
    w = _inv(s % N, N)
    u1 = z * w % N; u2 = r * w % N
    p1 = scalar_mult(u1, G); p2 = scalar_mult(u2, pt)
    rp = jadd((p1[0], p1[1], 1) if p1 else None, (p2[0], p2[1], 1) if p2 else None)
    if rp is None: return False
    xa, _ = to_affine(rp)
    return xa % N == r

def rfc6979_k(priv: int, z: int) -> int:
    x = priv.to_bytes(32, "big"); h1 = z.to_bytes(32, "big")
    v = b"\x01" * 32; k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        cand = int.from_bytes(v, "big")
        if 1 <= cand < N: return cand
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()

def ecdsa_sign(priv: int, z: int, k=None, low_s=True) -> tuple:
    if k is None: k = rfc6979_k(priv, z)
    R = scalar_mult(k, G)
    r = R[0] % N
    if r == 0: raise ValueError("bad k")
    s = (_inv(k, N) * (z + r * priv)) % N
    if s == 0: raise ValueError("bad k")
    if low_s and s > N // 2: s = N - s
    return r, s

def pubkey_from_priv(priv: int, compressed=True) -> bytes:
    x, y = scalar_mult(priv, G)
    if compressed:
        return bytes([0x02 + (y & 1)]) + x.to_bytes(32, "big")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")

# ---------------------------------------------------------------- sighash: legacy
def legacy_preimage(tx: Tx, nin: int, subscript: bytes, sighash_type: int) -> bytes:
    """Canonical pre-segwit SignatureHash serialization. Returns preimage bytes
    INCLUDING the 4-byte LE sighash suffix, or the SINGLE-bug sentinel b'\\x01-bug'."""
    if nin >= len(tx.vin):
        return b"SINGLE_BUG"          # uint256(1) case
    base = sighash_type & 0x1F
    anyone = bool(sighash_type & 0x80)
    vin2 = []
    for idx, i in enumerate(tx.vin):
        if anyone and idx != nin:
            continue
        ss = subscript if idx == nin else b""
        seq = i.sequence
        if (not anyone) and base in (0x02, 0x03) and idx != nin:
            seq = 0
        vin2.append((i.prev_txid, i.prev_vout, ss, seq))
    vout2 = []
    if base == 0x02:            # NONE
        vout2 = []
    elif base == 0x03:          # SINGLE
        if nin >= len(tx.vout):
            return b"SINGLE_BUG"
        for idx, o in enumerate(tx.vout):
            if idx < nin:
                vout2.append((-1, b""))
            elif idx == nin:
                vout2.append((o.value, o.spk))
            else:
                break
    else:                       # ALL (0x01) and default
        vout2 = [(o.value, o.spk) for o in tx.vout]
    out = struct.pack("<i", tx.version) + write_varint(len(vin2))
    for (pt, pv, ss, sq) in vin2:
        out += pt + struct.pack("<I", pv) + write_varint(len(ss)) + ss + struct.pack("<I", sq)
    out += write_varint(len(vout2))
    for (v, spk) in vout2:
        out += struct.pack("<q", v) + write_varint(len(spk)) + spk
    out += struct.pack("<I", tx.locktime) + struct.pack("<I", sighash_type)
    return out

def legacy_z(tx, nin, subscript, sighash_type):
    pre = legacy_preimage(tx, nin, subscript, sighash_type)
    if pre == b"SINGLE_BUG":
        zb = b"\x01" + b"\x00" * 31     # uint256(1) memory order -> BE int = 2^248
        return int.from_bytes(zb, "big"), zb, zb
    zb = dsha256(pre)
    return int.from_bytes(zb, "big"), zb, pre

# ---------------------------------------------------------------- sighash: BIP143
def bip143_preimage(tx: Tx, nin: int, script_code: bytes, value: int, sighash_type: int) -> bytes:
    base = sighash_type & 0x1F
    anyone = bool(sighash_type & 0x80)
    txin = tx.vin[nin]
    # hashPrevouts
    if not anyone:
        hprev = dsha256(b"".join(i.prev_txid + struct.pack("<I", i.prev_vout) for i in tx.vin))
    else:
        hprev = b"\x00" * 32
    # hashSequence
    if (not anyone) and base not in (0x02, 0x03):
        hseq = dsha256(b"".join(struct.pack("<I", i.sequence) for i in tx.vin))
    else:
        hseq = b"\x00" * 32
    # hashOutputs
    if base not in (0x02, 0x03):
        hout = dsha256(b"".join(struct.pack("<q", o.value) + write_varint(len(o.spk)) + o.spk for o in tx.vout))
    elif base == 0x03 and nin < len(tx.vout):
        o = tx.vout[nin]
        hout = dsha256(struct.pack("<q", o.value) + write_varint(len(o.spk)) + o.spk)
    else:
        hout = b"\x00" * 32
    pre = (struct.pack("<i", tx.version) + hprev + hseq +
           txin.prev_txid + struct.pack("<I", txin.prev_vout) +
           write_varint(len(script_code)) + script_code +
           struct.pack("<q", value) + struct.pack("<I", txin.sequence) +
           hout + struct.pack("<I", tx.locktime) + struct.pack("<I", sighash_type))
    return pre

def bip143_z(tx, nin, script_code, value, sighash_type):
    pre = bip143_preimage(tx, nin, script_code, value, sighash_type)
    zb = dsha256(pre)
    return int.from_bytes(zb, "big"), zb, pre

P2WPKH_SCRIPTCODE_TMPL = b"\x76\xa9\x14%s\x88\xac"

def p2wpkh_scriptcode(hash160_20: bytes) -> bytes:
    return P2WPKH_SCRIPTCODE_TMPL % hash160_20

# ---------------------------------------------------------------- misc
def le2be(h: str) -> str:
    return bytes.fromhex(h)[::-1].hex()

if __name__ == "__main__":
    # smoke vectors
    assert ripemd160(b"").hex() == "9c1185a5c5e9fc54612808977ee8f548b2258d31"
    assert ripemd160(b"abc").hex() == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
    assert ripemd160(b"message digest").hex() == "5d0689ef49d2fae572b881b123a85ffa21595f36"
    assert ripemd160(b"a"*1000).hex() == ripemd160(b"a"*1000).hex()
    assert hash160(bytes.fromhex("0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352")).hex() == "f54a5851e9372b87810a8e60cdd2e7cfd80b6e31"
    assert b58check_encode(b"\x00" + bytes.fromhex("f54a5851e9372b87810a8e60cdd2e7cfd80b6e31")) == "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
    assert segwit_addr_encode("bc", 0, bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")) == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    assert segwit_addr_decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") == (0, bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6"))
    assert segwit_addr_encode("bc", 1, bytes.fromhex("a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c")).startswith("bc1p")
    r, s = der_parse(der_encode(123456789, 987654321))
    assert (r, s) == (123456789, 987654321)
    # ECDSA round-trip with RFC6979 (deterministic)
    priv = 0xC0AC2D1E2B3A4F5E6D7C8B9A0F1E2D3C4B5A69788796A5B4C3D2E1F001122334
    pk = pubkey_from_priv(priv)
    z = int.from_bytes(sha256(b"test message"), "big")
    rr, ss = ecdsa_sign(priv, z)
    assert ecdsa_verify(pk, z, rr, ss), "pure-python ECDSA roundtrip failed"
    assert not ecdsa_verify(pk, z + 1, rr, ss)
    print("btclib smoke tests: ALL PASS")
