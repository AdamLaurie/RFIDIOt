# pace.py - PACE (ICAO 9303 Part 11) access protocol for RFIDIOt
#
#  Adam Laurie <adam@algroup.co.uk>
#  http://rfidiot.org/
#
#  This code is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  Password Authenticated Connection Establishment. Establishes a secure
#  messaging channel from the MRZ (or CAN), replacing/augmenting BAC.
#
#  Currently implemented: ECDH with Generic Mapping (GM) on a standardized
#  NIST/Brainpool curve, with 3DES-CBC + Retail-MAC secure messaging
#  (id-PACE-ECDH-GM-3DES-CBC-CBC) and AES-CBC + CMAC
#  (id-PACE-ECDH-GM-AES-CBC-CMAC-128/192/256).
#
#  perform_pace() runs the handshake over the supplied rfidiot.card (any
#  reader) and returns (ksenc, ksmac, ssc, sm) where sm describes the secure
#  messaging to use ("3DES" or "AES-<keylen>"); ssc is the initial Send
#  Sequence Counter (all zeroes).

import hashlib
import os

from Crypto.Cipher import DES3, AES
from Crypto.Hash import CMAC
from Crypto.PublicKey import ECC

# standardized domain parameter id (ICAO 9303 Part 11) -> pycryptodome curve name
PACE_CURVES = {
    12: "NIST P-256",
    15: "NIST P-384",
    18: "NIST P-521",
}

# PACE protocol OID (as a dotted string) -> (cipher, keybytes)
# OIDs live under id-PACE-ECDH-GM = 0.4.0.127.0.7.2.2.4.2
PACE_OIDS = {
    "0.4.0.127.0.7.2.2.4.2.1": ("3DES", 16),
    "0.4.0.127.0.7.2.2.4.2.2": ("AES", 16),
    "0.4.0.127.0.7.2.2.4.2.3": ("AES", 24),
    "0.4.0.127.0.7.2.2.4.2.4": ("AES", 32),
}


class PACEError(Exception):
    pass


# ----------------------------------------------------------------------------
# minimal BER-TLV helpers (single level)
# ----------------------------------------------------------------------------

def _read_tag(data, i):
    first = data[i]
    j = i + 1
    if first & 0x1F == 0x1F:  # multi-byte tag
        tag = first
        while data[j] & 0x80:
            tag = (tag << 8) | data[j]
            j += 1
        tag = (tag << 8) | data[j]
        j += 1
    else:
        tag = first
    return tag, j


def _read_len(data, i):
    first = data[i]
    if first < 0x80:
        return first, i + 1
    n = first & 0x7F
    return int.from_bytes(data[i + 1 : i + 1 + n], "big"), i + 1 + n


def _tlvs(data):
    "parse one level of TLVs -> dict {tag: value_bytes}"
    out = {}
    i = 0
    while i < len(data):
        tag, i = _read_tag(data, i)
        length, i = _read_len(data, i)
        out[tag] = data[i : i + length]
        i += length
    return out


def _enc_len(n):
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag, value):
    "build a TLV; tag is an int (1 or 2 bytes)"
    tb = tag.to_bytes(2, "big") if tag > 0xFF else bytes([tag])
    return tb + _enc_len(len(value)) + value


def _unwrap_7c(resp_hex, inner_tag):
    "pull the value of <inner_tag> out of a 7C dynamic authentication template"
    data = bytes.fromhex(resp_hex)
    top = _tlvs(data)
    if 0x7C not in top:
        raise PACEError("response is not a 7C dynamic authentication template: " + resp_hex)
    inner = _tlvs(top[0x7C])
    if inner_tag not in inner:
        raise PACEError("tag %02X not found in PACE response" % inner_tag)
    return inner[inner_tag]


# ----------------------------------------------------------------------------
# EC point <-> bytes
# ----------------------------------------------------------------------------

def _field_size(curve_name):
    return (int(ECC._curves[curve_name].p).bit_length() + 7) // 8


def _point_to_bytes(point, size):
    return b"\x04" + int(point.x).to_bytes(size, "big") + int(point.y).to_bytes(size, "big")


def _bytes_to_point(data, curve_name, size):
    if data[0] != 0x04:
        raise PACEError("only uncompressed EC points are supported")
    x = int.from_bytes(data[1 : 1 + size], "big")
    y = int.from_bytes(data[1 + size : 1 + 2 * size], "big")
    return ECC.EccPoint(x, y, curve=curve_name)


def _rand_scalar(order):
    order = int(order)
    return (int.from_bytes(os.urandom(((order.bit_length() + 7) // 8) + 8), "big") % (order - 1)) + 1


# ----------------------------------------------------------------------------
# key derivation and MAC (3DES Retail-MAC or AES-CMAC)
# ----------------------------------------------------------------------------

def _kdf(shared, counter, cipher, keybytes):
    "ICAO 9303 KDF: H(shared || counter), truncated; 3DES adjusts parity"
    seed = shared + counter.to_bytes(4, "big")
    if cipher == "3DES":
        k = hashlib.sha1(seed).digest()
        return _des_parity(k[:16])
    h = hashlib.sha1(seed).digest() if keybytes == 16 else hashlib.sha256(seed).digest()
    return h[:keybytes]


def _des_parity(key):
    out = bytearray()
    for b in key:
        parity = 0
        for i in range(1, 8):
            parity ^= (b >> i) & 1
        out.append((b & 0xFE) | (parity ^ 1))
    return bytes(out)


def _mac(cipher, kmac, data):
    "the PACE authentication-token MAC (8 bytes for 3DES Retail-MAC, 8 for AES-CMAC)"
    if cipher == "3DES":
        return _retail_mac(kmac, data)
    c = CMAC.new(kmac, ciphermod=AES)
    c.update(data)
    return c.digest()[:8]


def _retail_mac(key, data):
    "ISO 9797-1 MAC algorithm 3 (Retail MAC) with ISO padding method 2"
    data = bytes(data) + b"\x80"
    while len(data) % 8:
        data += b"\x00"
    k1 = key[:8]
    k2 = key[8:16]
    from Crypto.Cipher import DES
    e1 = DES.new(k1, DES.MODE_ECB)
    e2 = DES.new(k2, DES.MODE_ECB)
    h = b"\x00" * 8
    for i in range(0, len(data), 8):
        block = bytes(a ^ b for a, b in zip(h, data[i : i + 8]))
        h = e1.encrypt(block)
    return e1.encrypt(e2.decrypt(h))  # output transformation 3: E_K1( D_K2( H ) )


# ----------------------------------------------------------------------------
# APDU helpers over the rfidiot card
# ----------------------------------------------------------------------------

def _apdu(card, cla, ins, p1, p2, data_hex="", le=None, debug=False):
    lc = "%02X" % (len(data_hex) // 2) if data_hex else ""
    le_hex = "" if le is None else "%02X" % le
    if debug:
        print("   > %s%s%s%s %s %s" % (cla, ins, p1, p2, lc, data_hex), le_hex)
    ok = card.send_apdu("", "", "", "", cla, ins, p1, p2, lc, data_hex, le_hex)
    if debug:
        print("   < %s  [%s]" % (card.data, card.errorcode))
    return ok


# ----------------------------------------------------------------------------
# PACE
# ----------------------------------------------------------------------------

def perform_pace(card, mrz_info, oid_dotted, oid_content_hex, param_id,
                 password_ref=1, debug=False):
    """Run PACE-ECDH-GM over `card`. `mrz_info` is the MRZ key string
    (document-number+cd + DOB+cd + expiry+cd) for password_ref=1 (MRZ), or the
    CAN digits for password_ref=2. Returns (ksenc, ksmac, ssc, sm)."""
    if oid_dotted not in PACE_OIDS:
        raise PACEError("unsupported PACE protocol OID %s" % oid_dotted)
    cipher, keybytes = PACE_OIDS[oid_dotted]
    if param_id not in PACE_CURVES:
        raise PACEError("unsupported/unimplemented PACE domain parameter id %d "
                        "(only standardized NIST curves are wired up)" % param_id)
    curve = PACE_CURVES[param_id]
    size = _field_size(curve)
    order = ECC._curves[curve].order
    G = ECC.EccPoint(ECC._curves[curve].Gx, ECC._curves[curve].Gy, curve=curve)

    # PACE password -> nonce-decryption key K_pi
    if password_ref == 1:
        secret = hashlib.sha1(mrz_info.encode("latin-1")).digest()   # pi = SHA-1(MRZ info)
    else:
        secret = mrz_info.encode("latin-1")                          # CAN
    kpi = _kdf(secret, 3, cipher, keybytes)

    # --- MSE:Set AT - select PACE, protocol OID and password reference ---
    at = _tlv(0x80, bytes.fromhex(oid_content_hex)) + _tlv(0x83, bytes([password_ref]))
    if not _apdu(card, "00", "22", "C1", "A4", at.hex().upper(), debug=debug):
        raise PACEError("MSE:Set AT failed (%s)" % card.errorcode)

    # --- GA step 1: encrypted nonce ---
    if not _apdu(card, "10", "86", "00", "00", _tlv(0x7C, b"").hex().upper(), le=0, debug=debug):
        raise PACEError("GA(encrypted nonce) failed (%s)" % card.errorcode)
    z = _unwrap_7c(card.data, 0x80)
    s = _decrypt_nonce(cipher, kpi, z)

    # --- GA step 2: map the nonce (generic mapping) ---
    sk1 = _rand_scalar(order)
    pk1 = G * sk1
    data = _tlv(0x7C, _tlv(0x81, _point_to_bytes(pk1, size)))
    if not _apdu(card, "10", "86", "00", "00", data.hex().upper(), le=0, debug=debug):
        raise PACEError("GA(map nonce) failed (%s)" % card.errorcode)
    pk_picc = _bytes_to_point(_unwrap_7c(card.data, 0x82), curve, size)
    h = pk_picc * sk1                       # ECDH shared point
    g_mapped = (G * int.from_bytes(s, "big")) + h   # G' = s*G + H

    # --- GA step 3: ephemeral key agreement on the mapped generator ---
    sk2 = _rand_scalar(order)
    pk2 = g_mapped * sk2
    data = _tlv(0x7C, _tlv(0x83, _point_to_bytes(pk2, size)))
    if not _apdu(card, "10", "86", "00", "00", data.hex().upper(), le=0, debug=debug):
        raise PACEError("GA(key agreement) failed (%s)" % card.errorcode)
    pk2_picc = _bytes_to_point(_unwrap_7c(card.data, 0x84), curve, size)
    k_point = pk2_picc * sk2
    k = int(k_point.x).to_bytes(size, "big")        # shared secret = x coordinate

    ksenc = _kdf(k, 1, cipher, keybytes)
    ksmac = _kdf(k, 2, cipher, keybytes)

    # --- GA step 4: mutual authentication tokens ---
    oid = bytes.fromhex(oid_content_hex)
    t_pcd = _mac(cipher, ksmac, _auth_token_input(oid, _point_to_bytes(pk2_picc, size)))
    data = _tlv(0x7C, _tlv(0x85, t_pcd))
    if not _apdu(card, "00", "86", "00", "00", data.hex().upper(), le=0, debug=debug):
        raise PACEError("GA(mutual authenticate) rejected by chip - wrong password? (%s)"
                        % card.errorcode)
    t_picc = _unwrap_7c(card.data, 0x86)
    expect = _mac(cipher, ksmac, _auth_token_input(oid, _point_to_bytes(pk2, size)))
    if t_picc != expect:
        raise PACEError("chip authentication token mismatch - PACE failed")

    sm = "3DES" if cipher == "3DES" else "AES-%d" % (keybytes * 8)
    ssc = b"\x00" * (8 if cipher == "3DES" else 16)
    return ksenc, ksmac, ssc, sm


def _decrypt_nonce(cipher, kpi, z):
    iv = b"\x00" * (8 if cipher == "3DES" else 16)
    if cipher == "3DES":
        return DES3.new(kpi, DES3.MODE_CBC, iv).decrypt(z)
    return AES.new(kpi, AES.MODE_CBC, iv).decrypt(z)


def _auth_token_input(oid, point_bytes):
    "7F49 { 06 <oid> | 86 <ECDH public point> } - the data the token MACs"
    return _tlv(0x7F49, _tlv(0x06, oid) + _tlv(0x86, point_bytes))


def _oid_to_dotted(content):
    "OID value octets -> dotted string"
    vals = [content[0] // 40, content[0] % 40]
    v = 0
    for c in content[1:]:
        v = (v << 7) | (c & 0x7F)
        if not c & 0x80:
            vals.append(v)
            v = 0
    return ".".join(str(x) for x in vals)


def parse_cardaccess(data):
    """Parse EF.CardAccess (a SET OF SecurityInfo). Return the list of PACEInfo
    entries as (oid_dotted, oid_content_hex, parameter_id), supported ones first."""
    if isinstance(data, str):
        data = bytes.fromhex(data)
    top = _tlvs(data)
    setval = top.get(0x31, data)   # SET OF SecurityInfo
    out = []
    i = 0
    while i < len(setval):
        tag, j = _read_tag(setval, i)
        length, j = _read_len(setval, j)
        seq = setval[j : j + length]
        i = j + length
        if tag != 0x30:
            continue
        t, k = _read_tag(seq, 0)
        l, k = _read_len(seq, k)
        if t != 0x06:
            continue
        oidc = seq[k : k + l]
        dotted = _oid_to_dotted(oidc)
        if not dotted.startswith("0.4.0.127.0.7.2.2.4"):
            continue  # not a PACEInfo
        ints = []
        k += l
        while k < len(seq):
            tt, k2 = _read_tag(seq, k)
            ll, k2 = _read_len(seq, k2)
            if tt == 0x02:
                ints.append(int.from_bytes(seq[k2 : k2 + ll], "big"))
            k = k2 + ll
        param = ints[1] if len(ints) >= 2 else None
        out.append((dotted, oidc.hex().upper(), param))
    # supported configurations first
    out.sort(key=lambda e: (e[0] not in PACE_OIDS or e[2] not in PACE_CURVES))
    return out


def supported(entry):
    "is this (oid_dotted, oid_hex, param_id) PACEInfo one we can run?"
    return entry[0] in PACE_OIDS and entry[2] in PACE_CURVES
