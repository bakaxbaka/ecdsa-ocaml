#!/usr/bin/env python3
"""parse_extract.py — authoritative parse of cached raw transactions + signature/z extraction.

Raw hex (target/rawtx/<txid>.hex) is the authoritative serialization.
API JSON (transactions.jsonl) is metadata only and is cross-checked against raw parse.

Pipeline per tx:
  1. parse raw (btclib) -> strict checks: roundtrip bytes, txid, wtxid, size, weight vs JSON
  2. per input: determine prevout script type (from prevout tx raw when available, else JSON),
     extract signatures (legacy P2PKH/P2SH/P2PK/multisig, segwit BIP143, taproot noted)
  3. per signature: strict DER parse, sighash byte, z via btclib AND sighash_alt (must agree),
     ECDSA verify via OpenSSL (all) and pure-python (target-key sigs + sample)
Outputs: inputs.tsv outputs.tsv signatures.tsv z_values.tsv schnorr_sigs.tsv anomalies.tsv
         preimages/<txid>_<vin>.preimage.hex (target sigs), verification.json
"""
import json, os, sys, time, random, hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
WB = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(WB, "python"))
import btclib as B
import sighash_alt as ALT
from sighash_alt import MiniTx

TARGET = "17GGGHWtyi7e1rxnEpcKpE7fHq1UZBguAb"
TARGET_H160 = B.b58check_decode(TARGET)[1:]
assert len(TARGET_H160) == 20

T = os.path.join(WB, "target")
RAW = os.path.join(T, "rawtx")
RAWX = os.path.join(T, "rawtx_blockstream")
PRE = os.path.join(T, "preimages")
os.makedirs(PRE, exist_ok=True)

SHT_NAMES = {0x01: "SIGHASH_ALL", 0x02: "SIGHASH_NONE", 0x03: "SIGHASH_SINGLE",
             0x81: "SIGHASH_ALL|ANYONECANPAY", 0x82: "SIGHASH_NONE|ANYONECANPAY",
             0x83: "SIGHASH_SINGLE|ANYONECANPAY"}

from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

def openssl_verify(pk_bytes, z_bytes, der_sig):
    try:
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pk_bytes)
        pub.verify(der_sig, z_bytes, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        return f"ERR:{type(e).__name__}"

def load_all():
    txs = {}
    with open(os.path.join(T, "transactions.jsonl")) as f:
        for line in f:
            tx = json.loads(line)
            txs[tx["txid"]] = tx
    raws = {}
    missing = []
    for t in txs:
        p = os.path.join(RAW, t + ".hex")
        if os.path.exists(p):
            raws[t] = bytes.fromhex(open(p).read().strip())
        else:
            missing.append(t)
    return txs, raws, missing

def lenient_push_items(script):
    """Extract push-data items, skipping non-push opcodes (OP_k, OP_CHECKMULTISIG...).
    Used to recover candidate pubkeys from multisig redeem/witness scripts."""
    items, i, n = [], 0, len(script)
    while i < n:
        op = script[i]
        try:
            if op == 0x00:
                items.append(b""); i += 1
            elif op <= 0x4B:
                items.append(script[i+1:i+1+op]); i += 1 + op
            elif op == 0x4C and i + 1 < n:
                ln = script[i+1]; items.append(script[i+2:i+2+ln]); i += 2 + ln
            elif op == 0x4D and i + 2 < n:
                ln = int.from_bytes(script[i+1:i+3], "little"); items.append(script[i+3:i+3+ln]); i += 3 + ln
            elif op == 0x4E and i + 4 < n:
                ln = int.from_bytes(script[i+1:i+5], "little"); items.append(script[i+5:i+5+ln]); i += 5 + ln
            else:
                i += 1
        except Exception:
            i += 1
    return items

def main():
    t_start = time.time()
    txs, raws, missing = load_all()
    print(f"loaded {len(txs)} tx JSONs, {len(raws)} raw hexes, missing raw: {len(missing)}")
    if missing:
        print("missing examples:", missing[:5])

    # parse everything once
    parsed, parse_fail = {}, []
    for t, raw in raws.items():
        try:
            parsed[t] = B.Tx.parse(raw)
        except Exception as e:
            parse_fail.append((t, f"{type(e).__name__}: {e}"))
    print(f"parsed ok: {len(parsed)}, parse failures: {len(parse_fail)}")

    # structural verification vs JSON
    ver = {"tx_count": len(txs), "raw_count": len(raws), "parsed": len(parsed),
           "parse_fail": len(parse_fail), "roundtrip_fail": 0, "txid_fail": 0,
           "wtxid_fail": 0, "size_fail": 0, "weight_fail": 0, "blockstream_hex_checked": 0,
           "blockstream_hex_mismatch": 0}
    roundtrip_fail, txid_fail = [], []
    for t, tx in parsed.items():
        raw = raws[t]
        if tx.serialize(witness=tx.has_witness) != raw:
            ver["roundtrip_fail"] += 1; roundtrip_fail.append(t)
        if tx.txid_hex() != t:
            ver["txid_fail"] += 1; txid_fail.append(t)
        j = txs.get(t, {})
        if "size" in j and j["size"] != len(raw):
            ver["size_fail"] += 1
        w = len(tx.serialize(witness=False)) * 3 + len(tx.serialize(witness=True)) if tx.has_witness else len(raw) * 4
        if "weight" in j and j["weight"] != w:
            ver["weight_fail"] += 1
        if tx.has_witness and j.get("wtxid") and tx.wtxid().hex() != j["wtxid"]:
            ver["wtxid_fail"] += 1
    print("structural verification:", {k: ver[k] for k in ("roundtrip_fail","txid_fail","wtxid_fail","size_fail","weight_fail")})

    # blockstream cross-check bytes
    if os.path.isdir(RAWX):
        for fn in os.listdir(RAWX):
            t = fn[:-4]
            p2 = os.path.join(RAWX, fn)
            if t in raws and os.path.getsize(p2) > 10:
                ver["blockstream_hex_checked"] += 1
                if open(p2).read().strip().lower() != raws[t].hex():
                    ver["blockstream_hex_mismatch"] += 1
    print("blockstream hex cross-check:", ver["blockstream_hex_checked"], "files,",
          ver["blockstream_hex_mismatch"], "mismatches")

    # ---- iterate inputs, extract sigs ----
    f_in = open(os.path.join(T, "inputs.tsv"), "w")
    f_out = open(os.path.join(T, "outputs.tsv"), "w")
    f_sig = open(os.path.join(T, "signatures.tsv"), "w")
    f_z = open(os.path.join(T, "z_values.tsv"), "w")
    f_sch = open(os.path.join(T, "schnorr_sigs.tsv"), "w")
    f_an = open(os.path.join(T, "anomalies.tsv"), "w")

    f_in.write("txid\tvin\tprev_txid\tprev_vout\tsequence\tscriptSig_hex\twitness_items\t"
               "prevout_value\tprevout_spk_hex\tprevout_type\tprevout_address\tis_coinbase\t"
               "spends_target\tblock_height\tblock_time\n")
    f_out.write("txid\tvout\tvalue\tspk_hex\tspk_type\taddress\tis_target\tblock_height\n")
    f_sig.write("txid\tvin\tsig_index\tprev_txid\tprev_vout\tr_hex\tr_dec\ts_hex\ts_dec\t"
                "sighash_byte\tsighash_name\tder_strict\tlow_s\tpubkey\tpubkey_h160\t"
                "prevout_type\tz_method\tis_target_key\tverify_openssl\tverify_pure\t"
                "verify_zalt\tblock_height\tblock_time\n")
    f_z.write("txid\tvin\tr_hex\ts_hex\tsighash_type\tz_dec\tz_hex\tpreimage_hash\tpreimage_len\n")
    f_sch.write("txid\tvin\tsig_len\tsighash_byte\tblock_height\n")
    f_an.write("txid\tvin\tkind\tdetail\n")

    stats = {"inputs": 0, "coinbase": 0, "sigs": 0, "target_sigs": 0, "schnorr": 0,
             "anon": 0, "der_nonstrict": 0, "high_s": 0, "z_mismatch_impl": 0,
             "verify_openssl_ok": 0, "verify_openssl_fail": 0, "verify_pure_ok": 0,
             "verify_pure_fail": 0, "preimage_saved": 0, "target_prevout_raw_checked": 0,
             "target_prevout_raw_mismatch": 0, "shtypes": {}, "prevout_types": {},
             "target_pubkeys": {}, "json_prevout_mismatch": 0}
    rng = random.Random(2026)  # deterministic sampling for pure-python verify of non-target sigs
    other_sig_pool = []

    all_txids = sorted(parsed)
    t0 = time.time()
    for n, t in enumerate(all_txids):
        if n % 500 == 0:
            print(f"  ...{n}/{len(all_txids)} ({time.time()-t0:.0f}s)", flush=True)
        tx, raw, j = parsed[t], raws[t], txs.get(t, {})
        st = j.get("status", {})
        height, btime = st.get("block_height", ""), st.get("block_time", "")
        minitx = MiniTx(raw)

        # outputs
        for k, o in enumerate(tx.vout):
            typ = B.classify_spk(o.spk)
            addr = B.spk_to_address(o.spk)
            is_t = (typ == "p2pkh" and o.spk[3:23] == TARGET_H160)
            ja = j.get("vout", [{}]*len(tx.vout))
            if k < len(ja):
                jv = ja[k]
                if jv.get("value") != o.value or (jv.get("scriptpubkey") or "") != o.spk.hex():
                    stats["json_prevout_mismatch"] += 1
            f_out.write(f"{t}\t{k}\t{o.value}\t{o.spk.hex()}\t{typ}\t{addr}\t{int(is_t)}\t{height}\n")

        # inputs
        for i, txin in enumerate(tx.vin):
            stats["inputs"] += 1
            prev_txid_be = txin.prev_txid[::-1].hex()
            wit_hex = "|".join(w.hex() for w in txin.witness)
            if txin.is_coinbase:
                stats["coinbase"] += 1
                f_in.write(f"{t}\t{i}\tCOINBASE\t\t{txin.sequence:08x}\t{txin.script_sig.hex()}\t{wit_hex}\t"
                           f"\t\tcoinbase\t\t1\t0\t{height}\t{btime}\n")
                continue

            jvin = (j.get("vin") or [{}]*(i+1))[i] if i < len(j.get("vin", [])) else {}
            jpo = jvin.get("prevout") or {}
            # prevout spk: prefer authoritative prevout tx raw
            prev_raw_tx = parsed.get(prev_txid_be)
            if prev_raw_tx and txin.prev_vout < len(prev_raw_tx.vout):
                po = prev_raw_tx.vout[txin.prev_vout]
                spk, value = po.spk, po.value
                if prev_txid_be in raws:
                    stats["target_prevout_raw_checked"] += 1 if False else 0  # counted below for target only
                # cross-check JSON
                if jpo:
                    if jpo.get("value") != value or (jpo.get("scriptpubkey") or "") != spk.hex():
                        stats["json_prevout_mismatch"] += 1
            else:
                if jpo.get("scriptpubkey") is None:
                    f_an.write(f"{t}\t{i}\tno_prevout_data\tprev_tx_not_in_set_and_no_json\n"); stats["anon"] += 1
                    f_in.write(f"{t}\t{i}\t{prev_txid_be}\t{txin.prev_vout}\t{txin.sequence:08x}\t"
                               f"{txin.script_sig.hex()}\t{wit_hex}\t\t\tunknown\t\t0\t0\t{height}\t{btime}\n")
                    continue
                spk = bytes.fromhex(jpo["scriptpubkey"]); value = jpo.get("value")
            typ = B.classify_spk(spk)
            addr = B.spk_to_address(spk)
            spends_target = (typ == "p2pkh" and spk[3:23] == TARGET_H160)
            if spends_target:
                stats["target_prevout_raw_checked"] += 1
                if prev_raw_tx is None or value is None:
                    stats["target_prevout_raw_mismatch"] += 1
            stats["prevout_types"][typ] = stats["prevout_types"].get(typ, 0) + 1
            f_in.write(f"{t}\t{i}\t{prev_txid_be}\t{txin.prev_vout}\t{txin.sequence:08x}\t"
                       f"{txin.script_sig.hex()}\t{wit_hex}\t{value if value is not None else ''}\t"
                       f"{spk.hex()}\t{typ}\t{addr}\t0\t{int(spends_target)}\t{height}\t{btime}\n")

            # ---- signature extraction by prevout type ----
            sigs = []  # list of (sig_bytes_with_shtype, pubkey_or_None, z_method, script_code, subscript_or_None)
            try:
                if typ == "p2pkh":
                    items = B.parse_pushes(txin.script_sig)
                    if len(items) == 2 and len(items[0]) in range(9, 74) and len(items[1]) in (33, 65):
                        sigs.append((items[0], items[1], "legacy", None, spk))
                    else:
                        f_an.write(f"{t}\t{i}\todd_p2pkh_scriptsig\tn_items={len(items)}\n"); stats["anon"] += 1
                elif typ == "p2pk":
                    items = B.parse_pushes(txin.script_sig)
                    pk = spk[1:1+spk[0]]
                    if len(items) == 1:
                        sigs.append((items[0], pk, "legacy", None, spk))
                elif typ == "p2wpkh":
                    w = txin.witness
                    if len(w) == 2:
                        sc = B.p2wpkh_scriptcode(spk[2:])
                        sigs.append((w[0], w[1], "bip143", sc, None))
                    else:
                        f_an.write(f"{t}\t{i}\todd_p2wpkh_witness\tn={len(w)}\n"); stats["anon"] += 1
                elif typ == "p2sh":
                    items = B.parse_pushes(txin.script_sig)
                    if not items:
                        f_an.write(f"{t}\t{i}\tempty_p2sh_scriptsig\t\n"); stats["anon"] += 1
                    else:
                        redeem = items[-1]
                        if len(redeem) == 22 and redeem[0] == 0 and redeem[1] == 0x14:
                            w = txin.witness
                            if len(w) == 2:
                                sc = B.p2wpkh_scriptcode(redeem[2:])
                                sigs.append((w[0], w[1], "bip143", sc, None))
                            else:
                                f_an.write(f"{t}\t{i}\todd_nested_p2wpkh\tn={len(w)}\n"); stats["anon"] += 1
                        elif len(redeem) == 34 and redeem[0] == 0 and redeem[1] == 0x20:
                            w = txin.witness
                            if len(w) >= 2:
                                ws = w[-1]
                                for it in w[:-1]:
                                    if it and it[0] == 0x30 and 8 <= len(it) <= 73:
                                        sigs.append((it, None, "bip143", ws, None))
                            else:
                                f_an.write(f"{t}\t{i}\todd_nested_p2wsh\tn={len(w)}\n"); stats["anon"] += 1
                        else:
                            # legacy P2SH (multisig or custom): sigs are items[:-1], skip OP_0 dummy
                            for it in items[:-1]:
                                if it and it[0] == 0x30 and 8 <= len(it) <= 73:
                                    sigs.append((it, None, "legacy", None, redeem))
                elif typ == "p2wsh":
                    w = txin.witness
                    if len(w) >= 2:
                        ws = w[-1]
                        for it in w[:-1]:
                            if it and it[0] == 0x30 and 8 <= len(it) <= 73:
                                sigs.append((it, None, "bip143", ws, None))
                    else:
                        f_an.write(f"{t}\t{i}\todd_p2wsh_witness\tn={len(w)}\n"); stats["anon"] += 1
                elif typ == "p2tr":
                    w = txin.witness
                    if w and len(w[0]) in (64, 65):
                        shb = w[0][64] if len(w[0]) == 65 else ""
                        f_sch.write(f"{t}\t{i}\t{len(w[0])}\t{shb}\t{height}\n")
                        stats["schnorr"] += 1
                    else:
                        f_an.write(f"{t}\t{i}\todd_p2tr_witness\tn={len(w)}\n"); stats["anon"] += 1
                else:
                    f_an.write(f"{t}\t{i}\tunhandled_prevout_type\t{typ}\n"); stats["anon"] += 1
            except Exception as e:
                f_an.write(f"{t}\t{i}\textraction_error\t{type(e).__name__}: {e}\n"); stats["anon"] += 1
                sigs = []

            # ---- per-sig: DER, z, verify ----
            for si, (sigb, pk, zmethod, script_code, subscript) in enumerate(sigs):
                stats["sigs"] += 1
                if len(sigb) < 2:
                    f_an.write(f"{t}\t{i}\tsig_too_short\t{sigb.hex()}\n"); continue
                shtype = sigb[-1]
                der = sigb[:-1]
                stats["shtypes"][shtype] = stats["shtypes"].get(shtype, 0) + 1
                try:
                    r, s = B.der_parse(der)
                    der_strict = 1
                    if B.der_encode(r, s) != der:
                        der_strict = 0
                        f_an.write(f"{t}\t{i}\tder_noncanonical_reencode\t{der.hex()}\n"); stats["der_nonstrict"] += 1
                except B.DerError as e:
                    f_an.write(f"{t}\t{i}\tder_parse_fail\t{e}: {der.hex()[:80]}\n"); stats["anon"] += 1
                    continue
                low_s = 1 if s <= B.N // 2 else 0
                if not low_s: stats["high_s"] += 1

                # z reconstruction (both implementations)
                try:
                    if zmethod == "legacy":
                        z, zb, pre = B.legacy_z(tx, i, subscript, shtype)
                        z2, zb2 = ALT.legacy_z_alt(minitx, i, subscript, shtype)
                    else:
                        if value is None:
                            f_an.write(f"{t}\t{i}\tsegwit_missing_value\t\n"); continue
                        z, zb, pre = B.bip143_z(tx, i, script_code, value, shtype)
                        z2, zb2 = ALT.bip143_z_alt(minitx, i, script_code, value, shtype)
                except Exception as e:
                    f_an.write(f"{t}\t{i}\tz_error\t{type(e).__name__}: {e}\n"); stats["anon"] += 1
                    continue
                zalt_ok = 1 if (z == z2 and zb == zb2) else 0
                if not zalt_ok:
                    stats["z_mismatch_impl"] += 1
                    f_an.write(f"{t}\t{i}\tz_impl_mismatch\t{z:x} vs {z2:x}\n")

                # pubkey handling / target detection
                is_target = 0
                pk_h160 = ""
                if pk is not None:
                    if not B.pubkey_valid(pk):
                        f_an.write(f"{t}\t{i}\tinvalid_pubkey_point\t{pk.hex()[:40]}\n")
                    pk_h160 = B.hash160(pk).hex()
                    is_target = int(pk_h160 == TARGET_H160.hex())
                    if is_target:
                        stats["target_pubkeys"][pk.hex()] = stats["target_pubkeys"].get(pk.hex(), 0) + 1
                else:
                    # multisig: candidates from witnessScript (bip143) or redeemScript (legacy)
                    src_script = script_code if script_code is not None else subscript
                    try:
                        cands = [it for it in lenient_push_items(src_script)
                                 if len(it) in (33, 65) and B.pubkey_valid(it)] if src_script else []
                    except Exception:
                        cands = []
                    for c in cands:
                        if openssl_verify(c, zb, B.der_encode(r, s)) is True:
                            pk = c
                            pk_h160 = B.hash160(c).hex()
                            is_target = int(pk_h160 == TARGET_H160.hex())
                            break
                if is_target:
                    stats["target_sigs"] += 1
                    with open(os.path.join(PRE, f"{t}_{i}.preimage.hex"), "w") as fp:
                        fp.write((pre if isinstance(pre, bytes) else zb).hex() + "\n")
                    stats["preimage_saved"] += 1

                v_ossl = openssl_verify(pk, zb, B.der_encode(r, s)) if pk else "no_pubkey"
                if v_ossl is True: stats["verify_openssl_ok"] += 1
                elif v_ossl is False:
                    stats["verify_openssl_fail"] += 1
                    f_an.write(f"{t}\t{i}\topenssl_verify_fail\tr={r:x}\n")
                else:
                    stats["verify_openssl_nopubkey"] = stats.get("verify_openssl_nopubkey", 0) + 1
                    f_an.write(f"{t}\t{i}\tsig_unattributed\t{v_ossl}\tprevout={typ}\n")
                v_pure = ""
                if pk and (is_target or rng.random() < 0.05):
                    ok = B.ecdsa_verify(pk, z, r, s)
                    v_pure = int(ok)
                    if ok: stats["verify_pure_ok"] += 1
                    else:
                        stats["verify_pure_fail"] += 1
                        f_an.write(f"{t}\t{i}\tpure_verify_fail\tr={r:x}\n")

                sht_name = SHT_NAMES.get(shtype, f"UNKNOWN(0x{shtype:02x})")
                f_sig.write(f"{t}\t{i}\t{si}\t{prev_txid_be}\t{txin.prev_vout}\t"
                            f"{r:064x}\t{r}\t{s:064x}\t{s}\t0x{shtype:02x}\t{sht_name}\t{der_strict}\t"
                            f"{low_s}\t{pk.hex() if pk else ''}\t{pk_h160}\t{typ}\t{zmethod}\t{is_target}\t"
                            f"{v_ossl}\t{v_pure}\t{zalt_ok}\t{height}\t{btime}\n")
                f_z.write(f"{t}\t{i}\t{r:064x}\t{s:064x}\t0x{shtype:02x}\t{z}\t{zb.hex()}\t{zb.hex()}\t{len(pre) if isinstance(pre, bytes) else -1}\n")

    for f in (f_in, f_out, f_sig, f_z, f_sch, f_an):
        f.close()

    ver["stats"] = stats
    ver["parse_failures"] = parse_fail[:20]
    ver["roundtrip_fail_txids"] = roundtrip_fail[:20]
    ver["txid_fail_txids"] = txid_fail[:20]
    ver["runtime_s"] = round(time.time() - t_start, 1)
    with open(os.path.join(T, "verification.json"), "w") as f:
        json.dump(ver, f, indent=2, default=str)
    print(json.dumps({k: v for k, v in stats.items() if not isinstance(v, dict)}, indent=1))
    print("shtypes:", {hex(k): v for k, v in stats["shtypes"].items()})
    print("prevout_types:", stats["prevout_types"])
    print("target pubkeys:", list(stats["target_pubkeys"])[:4], "count:", len(stats["target_pubkeys"]))
    print("verification.json written. elapsed:", ver["runtime_s"], "s")

if __name__ == "__main__":
    main()
