#  iclass_omnikey.py - HID iCLASS / Picopass access via an OMNIKEY CardMan 5x21
#
#  Reads legacy HID iCLASS cards through an OMNIKEY contactless reader driven by
#  HID's modern CCID driver (ifdokccid 4.x) on Linux + pcscd.  iCLASS is NOT
#  reachable over standard PC/SC storage-card APDUs (those are MIFARE-only, and
#  return 6981); it needs the OMNIKEY proprietary SCardCLICCTransmit channel,
#  which HID exposes as a PC/SC escape (SCardControl).  We issue that escape
#  directly from Python, so no 32-bit libsyncapi (and its ancient libssl.0.9.8
#  dependency) is needed.
#
#  Transport (standard, CLA 80):
#     SCardControl(card, 0x42000c21,
#                  [0xf7] + len(apdu) as 8-byte LE + apdu   padded to 263 bytes)
#  The reply is <data...><SW1><SW2>.
#
#  Secured mode (CLA 84 - mandatory for READ access to the HID application):
#     a 3DES-EDE2-CBC + single-DES-CBC-MAC session between host and reader,
#     opened with the public-domain OMNIKEY reader session keys (KCUR).  The
#     card-side iCLASS authentication is done by the reader using a key held in
#     one of its slots (0x21 = the pre-loaded default HID Kd key).  Flow:
#        reset card -> Manage Session -> Authenticate <slot> -> Read ...
#     (do NOT re-open the session after Authenticate - that desyncs it.)
#
#  Ported from the holiman/loclass + ColdHeat/iclass (iclassified.c) lineage;
#  the iCLASS cipher / key diversification live in rfidiot.loclass.
#
#  NB roughly ONE secured session works per physical card placement: after a
#  Manage Session + reads, a second session desyncs the card's RF link so every
#  command (even standard ones) returns 6982, and a software power-cycle
#  (UNPOWER+reconnect) does not reliably clear it - remove and re-present the
#  card (or replug the reader) between runs.

import time

try:
    import smartcard.scard as scard
except ImportError:  # pragma: no cover - pyscard optional at import time
    scard = None

from Crypto.Cipher import DES, DES3

# OMNIKEY proprietary escape control code (ifdokccid 4.x, Linux)
OMNIKEY_CLICC_CTL = 0x42000C21
_SNDBUF = 0x107  # 263 - the fixed escape buffer size SCardCLICCTransmit uses

# Public-domain OMNIKEY reader session keys (KCUR), from ColdHeat/iclassified.c
KCUR_READ  = bytes.fromhex("A596154AB73CD8941F5678F5E3F1DF73")  # Manage Session P2=00
KCUR_WRITE = bytes.fromhex("B497CA728A8066DAC32E5B858C2C7028")  # Manage Session P2=01

# OMNIKEY reader key slots
SLOT_KD_DEFAULT = 0x21   # KMDC - pre-loaded default HID iCLASS Kd (debit) key


class IClassError(Exception):
    pass


def _tohex(b):
    return "".join("%02X" % x for x in b)


class OmnikeyIClass:
    """Minimal driver for HID iCLASS over an OMNIKEY reader (pcscd + ifdokccid)."""

    def __init__(self, debug=False, control_fn=None):
        if scard is None and control_fn is None:
            raise IClassError("pyscard (smartcard) not available")
        self.debug = debug
        self.ctx = None
        self.card = None        # SCARDHANDLE (standalone mode)
        self.pci = None
        self.readername = None
        self.csn = None
        self._key = bytearray(16)
        self._rdh = bytearray(4)
        # control_fn(controlCode, list_in) -> list_out lets this driver run on an
        # already-open pyscard connection (e.g. rfidiot-cli's card.pcsc_connection.
        # control) instead of opening its own PC/SC context via open().
        self._control_fn = control_fn

    def reset_session(self):
        "clear the secured-session state (key/rdh) - call after a card reset"
        self._key = bytearray(16)
        self._rdh = bytearray(4)

    def _escape(self, buf):
        "send one raw SCardControl escape; returns the response bytes"
        if self._control_fn is not None:
            return bytes(self._control_fn(OMNIKEY_CLICC_CTL, list(buf)))
        hr, resp = scard.SCardControl(self.card, OMNIKEY_CLICC_CTL, buf)
        if hr != scard.SCARD_S_SUCCESS:
            raise IClassError("escape failed: %s" % scard.SCardGetErrorMessage(hr))
        return bytes(resp or b"")

    # ---- connection -----------------------------------------------------
    def open(self, reset=True):
        "find the OMNIKEY contactless slot holding an iCLASS card and (re)set it"
        hr, self.ctx = scard.SCardEstablishContext(scard.SCARD_SCOPE_USER)
        if hr != scard.SCARD_S_SUCCESS:
            raise IClassError("cannot establish PC/SC context - is pcscd running?")
        hr, readers = scard.SCardListReaders(self.ctx, [])
        if hr != scard.SCARD_S_SUCCESS or not readers:
            raise IClassError("no PC/SC readers (OMNIKEY present? pcscd running?)")
        for r in readers:
            hr, card, proto = scard.SCardConnect(
                self.ctx, r, scard.SCARD_SHARE_SHARED,
                scard.SCARD_PROTOCOL_T0 | scard.SCARD_PROTOCOL_T1)
            if hr != scard.SCARD_S_SUCCESS:
                continue
            pci = {scard.SCARD_PROTOCOL_T0: scard.SCARD_PCI_T0,
                   scard.SCARD_PROTOCOL_T1: scard.SCARD_PCI_T1}.get(proto, scard.SCARD_PCI_T1)
            hr, resp = scard.SCardTransmit(card, pci, [0xFF, 0xCA, 0x00, 0x00, 0x00])
            if resp and len(resp) >= 2 and resp[-2:] == [0x90, 0x00]:
                self.csn = bytes(resp[:-2])
                if reset:
                    # full power-cycle: a prior secured session can leave the
                    # iCLASS chip desynced (every command -> 6982). UNPOWER +
                    # a fresh connect clears it more reliably than RESET alone.
                    scard.SCardDisconnect(card, scard.SCARD_UNPOWER_CARD)
                    time.sleep(0.15)
                    hr, card, proto = scard.SCardConnect(
                        self.ctx, r, scard.SCARD_SHARE_SHARED,
                        scard.SCARD_PROTOCOL_T0 | scard.SCARD_PROTOCOL_T1)
                    if hr != scard.SCARD_S_SUCCESS:
                        continue
                    pci = {scard.SCARD_PROTOCOL_T0: scard.SCARD_PCI_T0,
                           scard.SCARD_PROTOCOL_T1: scard.SCARD_PCI_T1}.get(proto, scard.SCARD_PCI_T1)
                self.card, self.pci, self.readername = card, pci, str(r)
                self._key = bytearray(16)
                self._rdh = bytearray(4)
                return self.csn
            scard.SCardDisconnect(card, scard.SCARD_LEAVE_CARD)
        raise IClassError("no OMNIKEY slot with an iCLASS card found "
                          "(card placed? contactless slot enabled? ifdokccid driver?)")

    def reset(self):
        "re-power the iCLASS chip to a clean state and clear any session"
        scard.SCardReconnect(self.card, scard.SCARD_SHARE_SHARED,
                             scard.SCARD_PROTOCOL_T0 | scard.SCARD_PROTOCOL_T1,
                             scard.SCARD_RESET_CARD)
        self._key = bytearray(16)
        self._rdh = bytearray(4)

    def close(self):
        if self.card is not None:
            try:
                scard.SCardDisconnect(self.card, scard.SCARD_UNPOWER_CARD)
            except Exception:
                pass
            self.card = None

    # ---- raw escape (standard, CLA 80) ----------------------------------
    def transceive(self, apdu):
        "send a standard-mode (CLA 80) iCLASS APDU; returns (data, sw) as bytes/int"
        apdu = bytes(apdu)
        buf = [0xF7] + list(len(apdu).to_bytes(8, "little")) + list(apdu)
        buf += [0] * (_SNDBUF - len(buf))
        resp = self._escape(buf)
        if self.debug:
            print("    80> %s" % _tohex(apdu))
            print("    80< %s" % _tohex(resp))
        if len(resp) < 2:
            return resp, None
        return resp[:-2], (resp[-2] << 8) | resp[-1]

    # ---- secured escape (CLA 84) ----------------------------------------
    def _ede2(self, data, encrypt):
        c = DES3.new(bytes(self._key), DES3.MODE_CBC, b"\0" * 8)
        return c.encrypt(data) if encrypt else c.decrypt(data)

    def transceive_secure(self, apdu):
        "send a secured-mode (CLA 84) iCLASS APDU; returns (data, sw)"
        snd = bytes(apdu)
        if snd[0] != 0x84:
            raise IClassError("secured transceive needs CLA 84")
        # On a Manage Session, load the base reader session key (KCUR).
        if snd[1] == 0x72 and snd[2] == 0x00:
            self._key[:] = KCUR_READ if snd[3] == 0x00 else KCUR_WRITE
        pay_len = snd[4]
        payload = snd[5:5 + pay_len]
        # plaintext region: [rdh(4)][len(1)][payload][0x80][00 pad to %8]
        region = bytearray(self._rdh) + bytes([pay_len]) + bytes(payload) + b"\x80"
        while len(region) % 8:
            region += b"\x00"
        # single-DES CBC MAC (K1), last block, appended
        mac = DES.new(bytes(self._key[0:8]), DES.MODE_CBC, b"\0" * 8).encrypt(bytes(region))[-8:]
        region += mac
        # 3DES-EDE2-CBC encrypt the whole region
        enc = self._ede2(bytes(region), True)
        out = bytearray(snd[0:4]) + bytes([len(region)]) + enc
        if 5 + pay_len == len(snd) - 1:           # trailing Le present?
            out += bytes([snd[5 + pay_len]])
        # derive the new session key from the plaintext (payload || MAC)
        if snd[1] == 0x72 and snd[2] == 0x00:
            full = bytearray(5) + region          # mimic C pbtSndPlain (+5 base)
            self._key[0:8] = full[10:18]
            self._key[8:16] = full[21:29]
        data, sw = self.transceive(out)
        # response: <enc...><SW1 SW2>; decrypt all but the 2 plaintext SW bytes
        resp = bytes(data) + (b"" if sw is None else bytes([sw >> 8, sw & 0xff]))
        if len(resp) < 2:
            return resp, None
        enc_resp, swb = resp[:-2], resp[-2:]
        if enc_resp and len(enc_resp) % 8 == 0:
            plain = self._ede2(enc_resp, False)
            if self.debug:
                print("    84= %s" % _tohex(plain))
            self._rdh[2] = plain[2] ^ 0xFF
            self._rdh[3] = plain[3] ^ 0xFF
            dlen = plain[4]
            return bytes(plain[5:5 + dlen]), (swb[0] << 8) | swb[1]
        return b"", (swb[0] << 8) | swb[1]

    # ---- high-level operations ------------------------------------------
    def identify(self):
        "standard-mode public info: returns dict with csn/config/aia (bytes)"
        info = {"csn": self.csn}
        data, sw = self.transceive([0x80, 0xA6, 0x00, 0x08, 0x08])   # Select Page -> config
        info["config"] = data if sw == 0x9000 else None
        data, sw = self.transceive([0x80, 0xA6, 0x00, 0x0C, 0x08])   # Select Page -> AIA
        info["aia"] = data if sw == 0x9000 else None
        return info

    def authenticate(self, slot=SLOT_KD_DEFAULT, write=False):
        "open the secured session and authenticate the card with a reader key slot"
        p2 = 0x01 if write else 0x00
        _, sw = self.transceive_secure([0x84, 0x72, 0x00, p2, 0x08, 0, 0, 0, 0, 0, 0, 0, 0])
        if sw != 0x9000:
            raise IClassError("Manage Session failed (SW=%04X)" % (sw or 0))
        _, sw = self.transceive_secure([0x84, 0x88, 0x00, slot, 0x00])
        if sw != 0x9000:
            raise IClassError("Authenticate slot 0x%02X failed (SW=%04X)" % (slot, sw or 0))
        return True

    def read_block(self, block, secure=True):
        "read one 8-byte block; secure=True uses the authenticated session"
        if secure:
            data, sw = self.transceive_secure([0x84, 0xB0, 0x00, block, 0x00, 0x08])
        else:
            data, sw = self.transceive([0x80, 0xB0, 0x00, block, 0x08])
        if sw != 0x9000:
            return None, sw
        return data, sw

    def dump(self, start=0, end=0x1F, secure=True):
        "read a block range; returns list of (block, data_or_None, sw)"
        out = []
        for blk in range(start, end + 1):
            data, sw = self.read_block(blk, secure=secure)
            out.append((blk, data, sw))
        return out


# ---- HID credential (PACS) decrypt + decode --------------------------------
#
# The HID iCLASS legacy credential (blocks 7..0x12 of the app1 area) is encrypted
# with a site-independent 16-byte 2-key-3DES "transport"/"master" key, in ECB per
# 8-byte block.  That key is NOT shipped here (same rule as passport MRZs / EMV
# PANs); supply it yourself via -k / $RFIDIOT_ICLASS_DECRYPTKEY (32 hex chars) or
# ~/.rfidiot/iclass_decryptionkey.bin (16 raw bytes, the pm3 location/name).

import os

KEYFILE_ENV = "RFIDIOT_ICLASS_DECRYPTKEY"
KEYFILE_PATHS = ["~/.rfidiot/iclass_decryptionkey.bin", "/etc/rfidiot/iclass_decryptionkey.bin"]
CRED_BLOCKS = range(6, 0x13)   # app1 credential area on a 2K card


def load_decrypt_key(arg=None):
    "resolve the HID iCLASS transport key (16 bytes) from arg/env/file, else None"
    if arg:
        k = bytes.fromhex(arg.replace(" ", ""))
        if len(k) != 16:
            raise IClassError("decrypt key must be 16 bytes (32 hex chars)")
        return k
    env = os.environ.get(KEYFILE_ENV)
    if env:
        k = bytes.fromhex(env.replace(" ", ""))
        if len(k) != 16:
            raise IClassError("$%s must be 32 hex chars" % KEYFILE_ENV)
        return k
    for p in KEYFILE_PATHS:
        p = os.path.expanduser(p)
        if os.path.exists(p):
            with open(p, "rb") as f:
                k = f.read()
            if len(k) == 16:
                return k
    return None


def decrypt_block(data8, key16):
    "3DES-ECB decrypt one 8-byte credential block with the HID transport key"
    if not data8 or len(data8) != 8:
        return data8
    # leave the trivial empty/blank blocks untouched (as pm3 does)
    if data8 in (b"\xff" * 8, b"\x00" * 8):
        return data8
    return DES3.new(bytes(key16), DES3.MODE_ECB).decrypt(bytes(data8))


def decode_pacs(block7_plain):
    """decode a decrypted PACS block (block 7) into Wiegand fields.

    HID encodes the credential right-justified with a leading '1' sentinel; the
    bits below it are the raw Wiegand.  Returns a dict (bitlen/raw/format/fc/cn)
    or None if the block carries no credential."""
    if bytes(block7_plain) in (b"\xff" * 8, b"\x00" * 8):
        return None
    val = int.from_bytes(bytes(block7_plain), "big")
    if val <= 1:
        return None
    bitlen = val.bit_length() - 1          # strip the leading sentinel bit
    raw = val & ((1 << bitlen) - 1)
    info = {"bitlen": bitlen, "raw": raw}
    if bitlen == 26:                        # H10301: P FC(8) CN(16) P
        info.update(format="H10301 (26-bit)", fc=(raw >> 17) & 0xFF, cn=(raw >> 1) & 0xFFFF)
    elif bitlen == 35:                      # HID Corporate 1000 (35-bit): P FC(12) CN(20) P
        info.update(format="Corporate 1000 (35-bit)", fc=(raw >> 21) & 0xFFF, cn=(raw >> 1) & 0xFFFFF)
    elif bitlen == 37:                      # H10304: P FC(16) CN(19) P
        info.update(format="H10304 (37-bit)", fc=(raw >> 20) & 0xFFFF, cn=(raw >> 1) & 0x7FFFF)
    else:
        info.update(format="unknown (%d-bit)" % bitlen)
    return info
