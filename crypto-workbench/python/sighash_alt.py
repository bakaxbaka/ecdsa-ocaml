#!/usr/bin/env python3
"""sighash_alt.py — INDEPENDENT second implementation of Bitcoin sighash z-values.

Deliberately written in a different style from btclib.py (own minimal tx re-parser,
segment-list preimage assembly) so that agreement between the two constitutes a
genuine cross-check rather than a tautology.

Only implements what this target needs + the standard sighash matrix:
  legacy (pre-segwit) SIGHASH_ALL/NONE/SINGLE x ANYONECANPAY
  BIP143 segwit       SIGHASH_ALL/NONE/SINGLE x ANYONECANPAY
"""
import hashlib
import struct as _st


def _h2(x: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(x).digest()).digest()


def _vi(n: int) -> bytes:
    if n < 0xFD:
        return bytes((n,))
    if n < 2**16:
        return b"\xfd" + _st.pack("<H", n)
    if n < 2**32:
        return b"\xfe" + _st.pack("<I", n)
    return b"\xff" + _st.pack("<Q", n)


def _rd_vi(buf: bytes, p: int):
    c = buf[p]
    if c < 0xFD:
        return c, p + 1
    fmt = {0xFD: "<H", 0xFE: "<I", 0xFF: "<Q"}[c]
    return _st.unpack_from(fmt, buf, p + 1)[0], p + 1 + _st.calcsize(fmt)


class MiniTx:
    """Minimal independent re-parser (fields as plain lists)."""

    def __init__(self, raw: bytes):
        pos = 4
        self.version = _st.unpack_from("<i", raw, 0)[0]
        self.segwit = raw[4] == 0 and raw[5] != 0
        if self.segwit:
            pos = 6
        n, pos = _rd_vi(raw, pos)
        self.inputs = []
        for _ in range(n):
            prev = raw[pos:pos + 32]
            idx = _st.unpack_from("<I", raw, pos + 32)[0]
            slen, pos = _rd_vi(raw, pos + 36)
            script = raw[pos:pos + slen]
            seq = _st.unpack_from("<I", raw, pos + slen)[0]
            self.inputs.append((prev, idx, script, seq))
            pos += slen + 4
        n, pos = _rd_vi(raw, pos)
        self.outputs = []
        for _ in range(n):
            val = _st.unpack_from("<q", raw, pos)[0]
            slen, pos2 = _rd_vi(raw, pos + 8)
            self.outputs.append((val, raw[pos2:pos2 + slen]))
            pos = pos2 + slen
        if self.segwit:
            self.witness = []
            for _ in range(len(self.inputs)):
                k, pos = _rd_vi(raw, pos)
                items = []
                for _ in range(k):
                    l, pos = _rd_vi(raw, pos)
                    items.append(raw[pos:pos + l])
                    pos += l
                self.witness.append(items)
        else:
            self.witness = [[] for _ in self.inputs]
        self.locktime = _st.unpack_from("<I", raw, pos)[0]
        pos += 4
        assert pos == len(raw), "trailing garbage"


SINGLE_BUG_Z_BYTES = b"\x01" + b"\x00" * 31


def _strip_codesep(script: bytes) -> bytes:
    """Opcode-aware removal of OP_CODESEPARATOR (0xAB), matching Bitcoin Core's
    FindAndDelete semantics: only opcode positions are stripped, never bytes
    inside push-data payloads."""
    out = bytearray()
    i = 0
    n = len(script)
    while i < n:
        op = script[i]
        if op == 0xAB:
            i += 1
            continue
        if op == 0:
            out.append(op); i += 1; continue
        if op <= 0x4B:
            ln, dstart = op, i + 1
        elif op == 0x4C:
            if i + 1 >= n: break
            ln, dstart = script[i+1], i + 2
        elif op == 0x4D:
            if i + 3 >= n: break
            ln, dstart = _st.unpack_from("<H", script, i+1)[0], i + 3
        elif op == 0x4E:
            if i + 5 >= n: break
            ln, dstart = _st.unpack_from("<I", script, i+1)[0], i + 5
        else:
            out.append(op); i += 1; continue
        dend = min(dstart + ln, n)
        out += script[i:dend]
        i = dend
    return bytes(out)


def legacy_z_alt(raw: bytes, nin: int, subscript: bytes, shtype: int):
    tx = MiniTx(raw) if isinstance(raw, bytes) else raw
    if nin >= len(tx.inputs):
        return int.from_bytes(SINGLE_BUG_Z_BYTES, "big"), SINGLE_BUG_Z_BYTES
    code = _strip_codesep(subscript)
    base, acp = shtype & 0x1F, shtype & 0x80

    sel_inputs = [nin] if acp else range(len(tx.inputs))
    seg = [_st.pack("<i", tx.version), _vi(len(list(sel_inputs)))]
    for i in sel_inputs:
        prev, idx, _script, seq = tx.inputs[i]
        script = code if i == nin else b""
        if (not acp) and base in (2, 3) and i != nin:
            seq = 0
        seg += [prev, _st.pack("<I", idx), _vi(len(script)), script, _st.pack("<I", seq)]

    if base == 2:
        outs = []
    elif base == 3:
        if nin >= len(tx.outputs):
            return int.from_bytes(SINGLE_BUG_Z_BYTES, "big"), SINGLE_BUG_Z_BYTES
        outs = [((-1, b"") if i < nin else tx.outputs[i]) for i in range(nin + 1)]
    else:
        outs = tx.outputs
    seg.append(_vi(len(outs)))
    for v, spk in outs:
        seg += [_st.pack("<q", v), _vi(len(spk)), spk]
    seg += [_st.pack("<I", tx.locktime), _st.pack("<I", shtype)]
    pre = b"".join(seg)
    zb = _h2(pre)
    return int.from_bytes(zb, "big"), zb


def bip143_z_alt(raw: bytes, nin: int, script_code: bytes, value: int, shtype: int):
    tx = MiniTx(raw) if isinstance(raw, bytes) else raw
    base, acp = shtype & 0x1F, shtype & 0x80
    zeros32 = b"\x00" * 32

    if acp:
        hp = zeros32
    else:
        hp = _h2(b"".join(p + _st.pack("<I", i) for p, i, _s, _q in tx.inputs))
    if acp or base in (2, 3):
        hs = zeros32
    else:
        hs = _h2(b"".join(_st.pack("<I", q) for _p, _i, _s, q in tx.inputs))
    if base in (0, 1):
        ho = _h2(b"".join(_st.pack("<q", v) + _vi(len(s)) + s for v, s in tx.outputs))
    elif base == 3 and nin < len(tx.outputs):
        v, s = tx.outputs[nin]
        ho = _h2(_st.pack("<q", v) + _vi(len(s)) + s)
    else:
        ho = zeros32

    prev, idx, _script, seq = tx.inputs[nin]
    pre = b"".join([
        _st.pack("<i", tx.version), hp, hs,
        prev, _st.pack("<I", idx),
        _vi(len(script_code)), script_code,
        _st.pack("<q", value), _st.pack("<I", seq),
        ho, _st.pack("<I", tx.locktime), _st.pack("<I", shtype),
    ])
    zb = _h2(pre)
    return int.from_bytes(zb, "big"), zb
