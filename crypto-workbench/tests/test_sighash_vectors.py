#!/usr/bin/env python3
"""test_sighash_vectors.py — ground-truth tests against official BIP143 vectors.

Vectors transcribed from bip-0143.mediawiki (cached: target/vectors/bip-0143.mediawiki).
Checks for each vector:
  * btclib preimage bytes == BIP143 preimage bytes (exact)
  * SHA256d(preimage) == published sigHash
  * sighash_alt (independent impl) agrees
  * published DER signature verifies against published pubkey via OpenSSL
    using z = BE-int(sigHash)  (validates endianness convention + everything)
  * private key -> pubkey derivation matches
  * pure-python secp256k1 verifier also accepts
  * legacy P2PK input (from same BIP143 example) validated via legacy sighash
"""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
WB = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(WB, "python"))
import btclib as B
import sighash_alt as ALT
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes

RESULTS = []
def check(name, cond):
    RESULTS.append((name, bool(cond)))
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    return bool(cond)

def ossl_verify(pk, zb, der):
    try:
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pk)
        pub.verify(der, zb, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return True
    except Exception:
        return False

# ---------------------------------------------------------------- P2WPKH vector
TX_P2WPKH = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000"
PRE_P2WPKH = "0100000096b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd3752b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3bef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a010000001976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac0046c32300000000ffffffff863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e51100000001000000"
SIG_P2WPKH = "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
SIGDER_P2WPKH = "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee"
PRIV_P2WPKH = 0x619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9
PUB_P2WPKH = "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"
VALUE_P2WPKH = 600000000

# ---------------------------------------------------------------- P2SH-P2WPKH
TX_P2SHWPKH = "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000"
PRE_P2SHWPKH = "01000000b0287b4a252ac05af83d2dcef00ba313af78a3e9c329afa216eb3aa2a7b4613a18606b350cd8bf565266bc352f0caddcf01e8fa789dd8a15386327cf8cabe198db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000001976a91479091972186c449eb1ded22b78e40d009bdf008988ac00ca9a3b00000000feffffffde984f44532e2173ca0d64314fcefe6d30da6f8cf27bafa706da61df8a226c839204000001000000"
SIG_P2SHWPKH = "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6"
SIGDER_P2SHWPKH = "3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb"
PRIV_P2SHWPKH = 0xeb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf
PUB_P2SHWPKH = "03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873"
VALUE_P2SHWPKH = 1000000000

# ---------------------------------------------------------------- P2SH-P2WSH 6of6
TX_P2WSH = "010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000"
WS_P2WSH = "56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae"
VALUE_P2WSH = 987654321
PRE_P2WSH = {
 1: "0100000074afdc312af5183c4198a40ca3c1a275b485496dd3929bca388c4b5e31f7aaa03bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e7066504436641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000cf" + WS_P2WSH + "b168de3a00000000ffffffffbc4d309071414bed932f98832b27b4d76dad7e6c1346f487a8fdbb8eb90307cc0000000001000000",
 2: "0100000074afdc312af5183c4198a40ca3c1a275b485496dd3929bca388c4b5e31f7aaa0000000000000000000000000000000000000000000000000000000000000000036641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000cf" + WS_P2WSH + "b168de3a00000000ffffffff00000000000000000000000000000000000000000000000000000000000000000000000002000000",
 3: "0100000074afdc312af5183c4198a40ca3c1a275b485496dd3929bca388c4b5e31f7aaa0000000000000000000000000000000000000000000000000000000000000000036641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000cf" + WS_P2WSH + "b168de3a00000000ffffffff9efe0c13a6b16c14a41b04ebe6a63f419bdacb2f8705b494a43063ca3cd4f7080000000003000000",
 0x81: "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000036641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000cf" + WS_P2WSH + "b168de3a00000000ffffffffbc4d309071414bed932f98832b27b4d76dad7e6c1346f487a8fdbb8eb90307cc0000000081000000",
 0x82: "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000036641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000cf" + WS_P2WSH + "b168de3a00000000ffffffff00000000000000000000000000000000000000000000000000000000000000000000000082000000",
 0x83: "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000036641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e01000000cf" + WS_P2WSH + "b168de3a00000000ffffffff9efe0c13a6b16c14a41b04ebe6a63f419bdacb2f8705b494a43063ca3cd4f7080000000083000000",
}
SIG_P2WSH = {
 1: "185c0be5263dce5b4bb50a047973c1b6272bfbd0103a89444597dc40b248ee7c",
 2: "e9733bc60ea13c95c6527066bb975a2ff29a925e80aa14c213f686cbae5d2f36",
 3: "1e1f1c303dc025bd664acb72e583e933fae4cff9148bf78c157d1e8f78530aea",
 0x81: "2a67f03e63a6a422125878b40b82da593be8d4efaafe88ee528af6e5a9955c6e",
 0x82: "781ba15f3779d5542ce8ecb5c18716733a5ee42a6f51488ec96154934e2c890a",
 0x83: "511e8e52ed574121fc1b654970395502128263f62662e076dc6baf05c2e6a99b",
}

# legacy P2PK input 0 of the P2WPKH example (signed serialization from BIP143)
TX_SIGNED = "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000"
LEGACY_SUBSCRIPT = "2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac"
LEGACY_PUB = "03c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432"
LEGACY_SIGDER = "30450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed"
LEGACY_PRIV = 0xbbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866


def _load_p2wsh_from_spec():
    """Parse preimages/sighashes directly from the cached BIP143 spec text so the
    test never depends on manual transcription. Overrides hardcoded dicts."""
    import re
    global PRE_P2WSH, SIG_P2WSH
    path = os.path.join(WB, "target", "vectors", "bip-0143.mediawiki")
    if not os.path.exists(path):
        print("  [WARN] spec file missing; using hardcoded transcription")
        return
    txt = open(path).read()
    anchor = txt.find(TX_P2WSH)
    assert anchor > 0, "P2WSH 6-of-6 unsigned tx not found in spec"
    txt = txt[anchor:]   # restrict matching to the 6-of-6 P2SH-P2WSH section
    names = {1: "ALL", 2: "NONE", 3: "SINGLE",
             0x81: "ALL|ANYONECANPAY", 0x82: "NONE|ANYONECANPAY", 0x83: "SINGLE|ANYONECANPAY"}
    n_found = 0
    for sht, nm in names.items():
        m = re.search(r"hash preimage for " + re.escape(nm) + r":\s*([0-9a-f]+)", txt)
        s = re.search(r"nHashType:\s*%02x000000\s*\n\s*sigHash:\s*([0-9a-f]+)" % sht, txt)
        if m and s:
            PRE_P2WSH[sht] = m.group(1); SIG_P2WSH[sht] = s.group(1); n_found += 1
    print(f"  [info] loaded {n_found}/6 P2WSH vectors from cached BIP143 spec")

_load_p2wsh_from_spec()

def main():
    ok = True
    print("== BIP143 P2WPKH (SIGHASH_ALL) ==")
    tx = B.Tx.parse(bytes.fromhex(TX_P2WPKH))
    sc = B.p2wpkh_scriptcode(bytes.fromhex("1d0f172a0ecb48aee1be1f2687d2963ae33f71a1"))
    z, zb, pre = B.bip143_z(tx, 1, sc, VALUE_P2WPKH, 1)
    ok &= check("preimage bytes == BIP143", pre.hex() == PRE_P2WPKH)
    ok &= check("sha256d(preimage) == published sigHash", zb.hex() == SIG_P2WPKH)
    z2, zb2 = ALT.bip143_z_alt(bytes.fromhex(TX_P2WPKH), 1, sc, VALUE_P2WPKH, 1)
    ok &= check("sighash_alt agrees", (z2, zb2) == (z, zb))
    pk = bytes.fromhex(PUB_P2WPKH)
    ok &= check("priv->pub derivation", B.pubkey_from_priv(PRIV_P2WPKH).hex() == PUB_P2WPKH)
    ok &= check("OpenSSL verify published sig with z=BE(sigHash)", ossl_verify(pk, zb, bytes.fromhex(SIGDER_P2WPKH)))
    r, s = B.der_parse(bytes.fromhex(SIGDER_P2WPKH))
    ok &= check("pure-python verify", B.ecdsa_verify(pk, z, r, s))
    rr, ss = B.ecdsa_sign(PRIV_P2WPKH, z)
    ok &= check("RFC6979 sign reproduces published sig", (rr, ss) == (r, s))

    print("== BIP143 P2SH-P2WPKH (SIGHASH_ALL) ==")
    tx = B.Tx.parse(bytes.fromhex(TX_P2SHWPKH))
    sc = B.p2wpkh_scriptcode(bytes.fromhex("79091972186c449eb1ded22b78e40d009bdf0089"))
    z, zb, pre = B.bip143_z(tx, 0, sc, VALUE_P2SHWPKH, 1)
    ok &= check("preimage bytes == BIP143", pre.hex() == PRE_P2SHWPKH)
    ok &= check("sha256d == sigHash", zb.hex() == SIG_P2SHWPKH)
    z2, zb2 = ALT.bip143_z_alt(bytes.fromhex(TX_P2SHWPKH), 0, sc, VALUE_P2SHWPKH, 1)
    ok &= check("sighash_alt agrees", (z2, zb2) == (z, zb))
    pk = bytes.fromhex(PUB_P2SHWPKH)
    ok &= check("priv->pub derivation", B.pubkey_from_priv(PRIV_P2SHWPKH).hex() == PUB_P2SHWPKH)
    ok &= check("OpenSSL verify", ossl_verify(pk, zb, bytes.fromhex(SIGDER_P2SHWPKH)))
    r, s = B.der_parse(bytes.fromhex(SIGDER_P2SHWPKH))
    ok &= check("pure-python verify", B.ecdsa_verify(pk, z, r, s))

    print("== BIP143 P2SH-P2WSH 6-of-6, all six sighash types ==")
    raw = bytes.fromhex(TX_P2WSH)
    tx = B.Tx.parse(raw)
    ws = bytes.fromhex(WS_P2WSH)
    for sht in (1, 2, 3, 0x81, 0x82, 0x83):
        z, zb, pre = B.bip143_z(tx, 0, ws, VALUE_P2WSH, sht)
        e1 = check(f"shtype 0x{sht:02x} preimage", pre.hex() == PRE_P2WSH[sht])
        e2 = check(f"shtype 0x{sht:02x} sigHash", zb.hex() == SIG_P2WSH[sht])
        z2, zb2 = ALT.bip143_z_alt(raw, 0, ws, VALUE_P2WSH, sht)
        e3 = check(f"shtype 0x{sht:02x} alt agrees", (z2, zb2) == (z, zb))
        ok &= e1 and e2 and e3

    print("== Legacy P2PK sighash (BIP143 example, input 0 of signed tx) ==")
    tx = B.Tx.parse(bytes.fromhex(TX_SIGNED))
    sub = bytes.fromhex(LEGACY_SUBSCRIPT)
    z, zb, pre = B.legacy_z(tx, 0, sub, 1)
    z2, zb2 = ALT.legacy_z_alt(bytes.fromhex(TX_SIGNED), 0, sub, 1)
    ok &= check("legacy alt agrees", (z2, zb2) == (z, zb))
    pk = bytes.fromhex(LEGACY_PUB)
    ok &= check("priv->pub derivation (legacy key)", B.pubkey_from_priv(LEGACY_PRIV).hex() == LEGACY_PUB)
    ok &= check("OpenSSL verify legacy P2PK sig via legacy_z", ossl_verify(pk, zb, bytes.fromhex(LEGACY_SIGDER)))
    r, s = B.der_parse(bytes.fromhex(LEGACY_SIGDER))
    ok &= check("pure-python verify legacy sig", B.ecdsa_verify(pk, z, r, s))

    print("== Legacy SIGHASH_SINGLE out-of-range bug + BIP143 zero-commitment ==")
    # synthetic: 1 input, 0 outputs, legacy SINGLE -> z_bytes = 01||00*31 (uint256(1))
    txb = B.Tx(2, [B.TxIn(bytes(range(32)), 0, b"", 0xFFFFFFFF)], [], 0, False)
    z, zb, pre = B.legacy_z(txb, 0, b"\x51", 3)
    ok &= check("legacy SINGLE-bug z_bytes == 0100..00", zb == b"\x01" + b"\x00"*31)
    ok &= check("legacy SINGLE-bug z == 2^248", z == 2**248)
    # sign/verify roundtrip on the bug hash proves path consistency
    priv = 0x1111111111111111111111111111111111111111111111111111111111111111
    pkb = B.pubkey_from_priv(priv)
    rr, ss = B.ecdsa_sign(priv, z)
    ok &= check("pure verify on SINGLE-bug z", B.ecdsa_verify(pkb, z, rr, ss))
    ok &= check("OpenSSL verify on SINGLE-bug z", ossl_verify(pkb, zb, B.der_encode(rr, ss)))
    # BIP143 equivalent: hashOutputs = zeros (no bug)
    zb143 = B.dsha256(B.bip143_preimage(txb, 0, b"\x51", 1000, 3))
    ok &= check("BIP143 out-of-range SINGLE != legacy bug value", zb143 != zb)

    n_pass = sum(1 for _, v in RESULTS if v); n = len(RESULTS)
    print(f"\nRESULT: {n_pass}/{n} checks passed")
    sys.exit(0 if (ok and n_pass == n) else 1)

if __name__ == "__main__":
    main()
