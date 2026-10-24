#!/usr/bin/python3
#  loclass.py - HID iClass / Picopass crypto for RFIDIOt: the iClass cipher
#  (MAC), key diversification (standard + elite) and the iClass CRC16.
#
#  Ported to Python by Adam Laurie <adam@algroup.co.uk> from the loclass
#  implementation in the Proxmark3 project (client/src/loclass/, common/crc16.c),
#  which is itself borrowed from Martin Holst Swende's loclass
#  (https://github.com/holiman/loclass, (C) 2014 Martin Holst Swende) and the
#  Proxmark3 contributors. The cipher is a reconstruction from the paper
#  "Dismantling iClass" (Garcia, de Koning Gans, Verdult, Meriac).
#
#    This code is free software; you can redistribute it and/or modify it under
#    the terms of the GNU General Public License (v2 or later, per RFIDIOt; the
#    loclass sources are GPLv3+).
#
#  WARNING: for experimentation / education / authorised security testing only.
#
#  Validated offline against the Proxmark3 self-test vectors (see selftest()):
#  the "Dismantling iClass" MAC vector, and known iClass CRC values.

# --------------------------------------------------------------------------- #
#  bit helpers
# --------------------------------------------------------------------------- #
def reflect8(b):
    "reverse the 8 bits of a byte (pm3 reflect8 / reverse_arraybytes per byte)"
    b = ((b & 0xF0) >> 4) | ((b & 0x0F) << 4)
    b = ((b & 0xCC) >> 2) | ((b & 0x33) << 2)
    b = ((b & 0xAA) >> 1) | ((b & 0x55) << 1)
    return b & 0xFF


# --------------------------------------------------------------------------- #
#  iClass CRC16  (CRC-16/ICLASS: poly 0x1021 reflected 0x8408, init 0x4807,
#  refin/refout, no xorout). Appended LITTLE-endian, computed over the bytes
#  AFTER the command byte. (The nfc-iclass ~/byte-swap/^0xBC3 formula is only
#  correct for single-byte coverage - this is the pm3 / field-proven version.)
# --------------------------------------------------------------------------- #
def crc16_iclass(data):
    "iClass CRC16 of a bytes/bytearray; returns the 16-bit value"
    # init 0x4807, reflected (refin) to 0xE012 for the LSB-first loop; poly 0x1021
    # reflected to 0x8408; refout == refin so no final reflect; no xorout.
    crc = 0xE012
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc >>= 1
    return crc & 0xFFFF


def add_crc(cmd_plus_data):
    """append the iClass CRC to a command frame. The CRC covers everything AFTER
    the first (command) byte, and is appended low byte first. Returns bytes."""
    data = bytes(cmd_plus_data)
    crc = crc16_iclass(data[1:])
    return data + bytes([crc & 0xFF, (crc >> 8) & 0xFF])


# --------------------------------------------------------------------------- #
#  iClass cipher (Dismantling iClass). State = [l, r, b (8-bit), t (16-bit)].
# --------------------------------------------------------------------------- #
def _T(t):
    "top-register feedback"
    return (((t >> 15) & 1) ^ ((t >> 14) & 1) ^ ((t >> 10) & 1) ^ ((t >> 8) & 1)
            ^ ((t >> 5) & 1) ^ ((t >> 4) & 1) ^ ((t >> 1) & 1) ^ (t & 1))


def _B(b):
    "bottom-register feedback"
    return ((b & 0x40) >> 6) ^ ((b & 0x20) >> 5) ^ ((b & 0x10) >> 4) ^ (b & 0x01)


def _select(x, y, r):
    "selection function -> 3-bit key index"
    r0 = (r >> 7) & 1
    r1 = (r >> 6) & 1
    r2 = (r >> 5) & 1
    r3 = (r >> 4) & 1
    r4 = (r >> 3) & 1
    r5 = (r >> 2) & 1
    r6 = (r >> 1) & 1
    r7 = r & 1
    z0 = (r0 & r2) ^ (r1 & (r3 ^ 1)) ^ (r2 | r4)
    z1 = (r0 | r2) ^ (r5 | r7) ^ r1 ^ r6 ^ x ^ y
    z2 = (r3 & (r5 ^ 1)) ^ (r4 & r6) ^ r7 ^ x
    return ((z0 << 2) & 4) | ((z1 << 1) & 2) | (z2 & 1)


def _init(k):
    "initial cipher state from the 8-byte (diversified) key"
    l = ((k[0] ^ 0x4C) + 0xEC) & 0xFF
    r = ((k[0] ^ 0x4C) + 0x21) & 0xFF
    return [l, r, 0x4C, 0xE012]


def _successor(k, s, y):
    "one cipher step with input bit y"
    l, r, b, t = s
    r0 = (r >> 7) & 1
    r4 = (r >> 3) & 1
    r7 = r & 1
    nt = ((t >> 1) | ((_T(t) ^ r0 ^ r4) << 15)) & 0xFFFF
    nb = ((b >> 1) | ((_B(b) ^ r7) << 7)) & 0xFF
    sel = _select(_T(t), y, r)
    nl = ((k[sel] ^ nb) + l + r) & 0xFF
    nr = ((k[sel] ^ nb) + l) & 0xFF
    return [nl, nr, nb, nt]


def _suc(k, s, buf):
    "apply the successor function over every bit of buf (MSB first, head to tail)"
    for i in range(len(buf) * 8):
        bit = (buf[i >> 3] >> (7 - (i & 7))) & 1
        s = _successor(k, s, bit)
    return s


def _output32(k, s):
    "produce 32 output bits (feeding 32 zero input bits), packed MSB first -> 4 bytes"
    out = bytearray(4)
    for i in range(32):
        bit = (s[1] >> 2) & 1               # output bit = r5  (s.r >> 2 & 1)
        out[i >> 3] |= bit << (7 - (i & 7))
        s = _successor(k, s, 0)
    return bytes(out)


def _mac(div_key, input_buf):
    "raw MAC: cipher the input then read 32 output bits (4 bytes)"
    s = _suc(div_key, _init(div_key), input_buf)
    return _output32(div_key, s)


def doMAC_N(data, div_key):
    """iClass MAC over `data` (any length) with the 8-byte diversified key.
    Input and output bytes are bit-reflected, as the iClass wire format needs."""
    buf = bytes(reflect8(x) for x in data)
    out = _mac(div_key, buf)
    return bytes(reflect8(x) for x in out)


def doMAC(cc_nr, div_key):
    "MAC over a 12-byte card-challenge||nonce block (= doMAC_N)"
    return doMAC_N(cc_nr, div_key)


def doReaderMAC(cc, div_key):
    "reader authentication MAC: MAC over cc(8) || nR(4 = 0)"
    return doMAC(bytes(cc) + b"\x00\x00\x00\x00", div_key)


# --------------------------------------------------------------------------- #
#  key diversification (hash0) - ported from pm3 loclass ikeys.c
#  div_key = hash0( DES(CSN, key) ). 6-bit "bytes" are packed into a uint64 as
#  XXXX XXXX z0..z7 (last 48 bits); see getSixBitByte / pushbackSixBitByte.
# --------------------------------------------------------------------------- #
_MASK64 = 0xFFFFFFFFFFFFFFFF
_pi = [
    0x0F, 0x17, 0x1B, 0x1D, 0x1E, 0x27, 0x2B, 0x2D,
    0x2E, 0x33, 0x35, 0x39, 0x36, 0x3A, 0x3C, 0x47,
    0x4B, 0x4D, 0x4E, 0x53, 0x55, 0x56, 0x59, 0x5A,
    0x5C, 0x63, 0x65, 0x66, 0x69, 0x6A, 0x6C, 0x71,
    0x72, 0x74, 0x78,
]


def _getSixBitByte(c, n):
    return (c >> (42 - 6 * n)) & 0x3F


def _pushbackSixBitByte(c, z, n):
    shift = 42 - 6 * n
    masked = (z & 0x3F) << shift
    eraser = (~(0x3F << shift)) & _MASK64
    return ((c & eraser) | masked) & _MASK64


def _swapZvalues(c):
    newz = 0
    for src in range(8):
        newz = _pushbackSixBitByte(newz, _getSixBitByte(c, src), 7 - src)
    newz |= (c & 0xFFFF000000000000)
    return newz & _MASK64


def _ck(i, j, z):
    if i == 1 and j == -1:
        return z
    if j == -1:
        return _ck(i - 1, i - 2, z)
    if _getSixBitByte(z, i) == _getSixBitByte(z, j):
        newz = 0
        for c in range(4):
            if c == i:
                newz = _pushbackSixBitByte(newz, j, c)
            else:
                newz = _pushbackSixBitByte(newz, _getSixBitByte(z, c), c)
        return _ck(i, j - 1, newz)
    return _ck(i, j - 1, z)


def _check(z):
    ck1 = _ck(3, 2, z) & 0x00000000FFFFFF000000
    ck2 = _ck(3, 2, (z << 24) & _MASK64) & 0x00000000FFFFFF000000
    return ck1 | (ck2 >> 24)


def _permute(p, z):
    "permute: consume p's 8 bits LSB-first, emit 48 bits (6-bit chunks) -> top of an 8-byte buffer"
    bits = []
    l, r = 0, 4
    for k in range(8):
        if (p >> k) & 1:
            v = _getSixBitByte(z, l) + 1
            l += 1
        else:
            v = _getSixBitByte(z, r)
            r += 1
        for mask in (0x20, 0x10, 0x08, 0x04, 0x02, 0x01):
            bits.append(1 if (v & mask) else 0)
    buf = bytearray(8)
    for i, bit in enumerate(bits):
        buf[i >> 3] |= bit << (7 - (i & 7))
    return bytes(buf)


def hash0(c):
    "iClass hash0: 64-bit input c -> 8-byte diversified key"
    c = _swapZvalues(c)
    x = (c >> 56) & 0xFF
    y = (c >> 48) & 0xFF
    zP = 0
    for n in range(4):
        zn = _getSixBitByte(c, n)
        zn4 = _getSixBitByte(c, n + 4)
        zP = _pushbackSixBitByte(zP, (zn % (63 - n)) + n, n)
        zP = _pushbackSixBitByte(zP, (zn4 % (64 - n)) + n, n + 4)
    zCaret = _check(zP)
    p = _pi[x % 35]
    if x & 1:
        p = (~p) & 0xFF
    zTilde = int.from_bytes(_permute(p, zCaret), "big") >> 16
    k = bytearray(8)
    for i in range(8):
        ki = (y << (7 - i)) & 0x80
        zTilde_i = (_getSixBitByte(zTilde, i) << 1) & 0xFF
        p_i = (p >> i) & 1
        if ki:                                  # y bit = 1
            ki |= (~zTilde_i) & 0x7E
            ki |= p_i & 1
            ki = (ki + 1) & 0xFF
        else:
            ki |= zTilde_i & 0x7E
            ki |= (~p_i) & 1
        k[i] = ki & 0xFF
    return bytes(k)


def diversifyKey(csn, key):
    "standard iClass key diversification: hash0(DES(csn, key)) -> 8-byte div_key"
    from Crypto.Cipher import DES
    crypted = DES.new(bytes(key), DES.MODE_ECB).encrypt(bytes(csn))
    return hash0(int.from_bytes(crypted, "big"))


# --------------------------------------------------------------------------- #
#  ELITE / high-security key diversification (pm3 optimized_elite.c)
#  permute between NIST and iClass key formats, hash1 (CSN -> key indices),
#  hash2 (custom master key -> 128-byte key table), divkey_elite.
# --------------------------------------------------------------------------- #
def permutekey(key):
    "permute a key from standard NIST format to iClass format"
    dest = bytearray(8)
    for i in range(8):
        v = 0
        for n in range(8):
            v |= ((key[n] >> (7 - i)) & 1) << n
        dest[i] = v
    return bytes(dest)


def permutekey_rev(key):
    "permute a key from iClass format back to standard NIST format"
    dest = bytearray(8)
    for i in range(8):
        v = 0
        for n in range(8):
            v |= ((key[n] >> (7 - i)) & 1) << (7 - n)
        dest[7 - i] = v
    return bytes(dest)


def _rr(v):
    return ((v >> 1) | ((v & 1) << 7)) & 0xFF


def _rl(v):
    return ((v << 1) | ((v & 0x80) >> 7)) & 0xFF


def _swap(v):
    return (((v >> 4) & 0xFF) | ((v & 0xFF) << 4)) & 0xFF


def hash1(csn):
    "hash1: CSN -> 8 key-table indices (each 0..127)"
    k = bytearray(8)
    k[0] = csn[0] ^ csn[1] ^ csn[2] ^ csn[3] ^ csn[4] ^ csn[5] ^ csn[6] ^ csn[7]
    k[1] = sum(csn) & 0xFF
    k[2] = _rr(_swap((csn[2] + k[1]) & 0xFF))
    k[3] = _rl(_swap((csn[3] + k[0]) & 0xFF))
    k[4] = (~_rr((csn[4] + k[2]) & 0xFF) + 1) & 0xFF
    k[5] = (~_rl((csn[5] + k[3]) & 0xFF) + 1) & 0xFF
    k[6] = _rr((csn[6] + (k[4] ^ 0x3C)) & 0xFF)
    k[7] = _rl((csn[7] + (k[5] ^ 0xC3)) & 0xFF)
    return bytes(b & 0x7F for b in k)


def _rk(key, n):
    "rotate-left each of the 8 key bytes n times"
    out = bytearray(key)
    for _ in range(n):
        out = bytearray(_rl(b) for b in out)
    return bytes(out)


def _des_iclass(iclass_key, data, encrypt):
    "DES enc/dec with an iClass-format key (permuted back to NIST first)"
    from Crypto.Cipher import DES
    c = DES.new(permutekey_rev(iclass_key), DES.MODE_ECB)
    return c.encrypt(bytes(data)) if encrypt else c.decrypt(bytes(data))


def hash2(key64):
    "hash2: 8-byte custom master key -> 128-byte high-security key table"
    key64 = bytes(key64)
    neg = bytes((~b) & 0xFF for b in key64)
    z = [b""] * 8
    y = [b""] * 8
    z[0] = _des_iclass(key64, neg, True)
    y[0] = _des_iclass(z[0], neg, False)
    for i in range(1, 8):
        temp = _rk(key64, i)
        z[i] = _des_iclass(temp, z[i - 1], False)
        y[i] = _des_iclass(temp, y[i - 1], True)
    table = bytearray(128)
    for i in range(8):
        table[i * 16:i * 16 + 8] = y[i]
        table[i * 16 + 8:i * 16 + 16] = z[i]
    return bytes(table)


def divkey_elite(csn, key):
    "elite iClass key diversification using a custom (elite) master key"
    keytable = hash2(key)
    key_index = hash1(csn)
    key_sel = bytes(keytable[key_index[i]] for i in range(8))
    return diversifyKey(csn, permutekey_rev(key_sel))


# --------------------------------------------------------------------------- #
#  self-test (offline, no hardware) - run:  python3 -m rfidiot.loclass
# --------------------------------------------------------------------------- #
def selftest():
    ok = True

    # pm3 cipher.c testMAC - "Dismantling iClass" vector
    cc_nr = bytes([0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0])
    div_key = bytes([0xE0, 0x33, 0xCA, 0x41, 0x9A, 0xEE, 0x43, 0xF9])
    want = bytes([0x1D, 0x49, 0xC9, 0xDA])
    got = doMAC(cc_nr, div_key)
    print("MAC   : got %s want %s  %s" % (got.hex().upper(), want.hex().upper(),
                                          "OK" if got == want else "FAIL"))
    ok = ok and got == want

    # iClass CRC on the wire (pm3 AddCrc appends low byte first, over bytes after
    # the command byte). Known pm3 frames: IDENTIFY = 0C 00 73 33 (CRC over 00),
    # READ block 1 = 0C 01 FA 22 (CRC over 01, pm3 iclass.c:1273).
    read1 = add_crc(bytes([0x0C, 0x01])).hex().upper()
    ident = add_crc(bytes([0x0C, 0x00])).hex().upper()
    print("READ1 : %s want 0C01FA22  %s" % (read1, "OK" if read1 == "0C01FA22" else "FAIL"))
    print("IDENT : %s want 0C007333  %s" % (ident, "OK" if ident == "0C007333" else "FAIL"))
    ok = ok and read1 == "0C01FA22" and ident == "0C007333"

    # pm3 ikeys.c testCryptedCSN: hash0(input) -> div_key (as uint64)
    for inp, exp in (
        (0x0102030405060708, 0x0BDD6512073C460A),
        (0x1122334455667788, 0x2BEE256D40AC1F3A),
        (0xABCDABCDABCDABCD, 0xA91C9EC66F7DA592),
        (0x14E2ADFC5BB7E134, 0x6AC90C6508BD9EA3),
    ):
        got = int.from_bytes(hash0(inp), "big")
        res = "OK" if got == exp else "FAIL"
        print("hash0 : %016X -> %016X want %016X  %s" % (inp, got, exp, res))
        ok = ok and got == exp

    # pm3 ikeys.c testcases[0]: hash0 of the crypted-CSN field -> div_key
    h0z = hash0(0).hex().upper()
    print("hash0(0): %s want 0204060801030507  %s"
          % (h0z, "OK" if h0z == "0204060801030507" else "FAIL"))
    ok = ok and h0z == "0204060801030507"

    # DES step vector (pm3 doTestsWithKnownInputs testDES2)
    from Crypto.Cipher import DES
    deskey = bytes.fromhex("6C8D44F92A2D01BF")
    desin = (0xBBBBAAAABBBBEEEE).to_bytes(8, "big")
    desout = DES.new(deskey, DES.MODE_ECB).encrypt(desin).hex().upper()
    print("DES   : %s want D6AD3CA619659E6B  %s"
          % (desout, "OK" if desout == "D6AD3CA619659E6B" else "FAIL"))
    ok = ok and desout == "D6AD3CA619659E6B"

    # end-to-end diversifyKey = hash0(DES(csn, key))
    dk = diversifyKey(desin, deskey)
    dkref = hash0(0xD6AD3CA619659E6B)
    print("divKey: %s (= hash0(DES))  %s"
          % (dk.hex().upper(), "OK" if dk == dkref else "FAIL"))
    ok = ok and dk == dkref

    # elite: permutekey vector (pm3 optimized_elite.c)
    pk = permutekey(bytes.fromhex("6C8D44F92A2D01BF")).hex().upper()
    print("permKey: %s want 8A0DB988BBA790EA  %s"
          % (pk, "OK" if pk == "8A0DB988BBA790EA" else "FAIL"))
    ok = ok and pk == "8A0DB988BBA790EA"

    # elite: hash2 HS key table vector (pm3 optimized_elite.c comment)
    want_kt = ("F13559A10D5A267F18600B968AC025C1BFA13BB0FF852875F21FC68F0E748F21"
               "147A5516C8A97DB3130C5DC9318DA9B2A356830F557EDE457121D26DC1571C9C"
               "782F6451427B6430FA265176D3E0FBB6319FBF2F7E4F94B4BD4F7591E31BEB42"
               "3F886FB86C2C930D692CD5203CC161954308A02FFEB326D7980B347B4770A0AB")
    kt = hash2(bytes.fromhex("5B7C62C491C11B39")).hex().upper()
    print("hash2 : %s... %s" % (kt[:16], "OK" if kt == want_kt else "FAIL"))
    ok = ok and kt == want_kt

    print("SELFTEST:", "PASS" if ok else "FAIL")
    return ok


if __name__ == "__main__":
    import sys
    sys.exit(0 if selftest() else 1)
