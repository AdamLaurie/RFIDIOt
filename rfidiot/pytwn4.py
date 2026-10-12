#  pytwn4.py - minimal pyserial driver for the ELATEC TWN4 family (MultiTech etc.)
#  used as an ISO/IEC 14443 reader by RFIDIOt (READER_TWN4).
#
#  Adam Laurie <adam@algroup.co.uk>
#  http://rfidiot.org/
#
#    This code is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This code is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#  Protocol: TWN4 "Simple Protocol" (firmware TWN4_..._PRSwww - the PRS app), in
#  its default ASCII mode with CRC off, over USB CDC (or true serial). Verified on
#  a TWN4 MultiTech 2 (version string TWN4/B1.50/NCF5.25/PRS1.04/AV).
#    command:  hex(API number, function number, parameters...) + CR
#    response: hex(protocol error byte, return values...) + CR
#  Parameter types (Simple Protocol doc): Byte; UInt16/UInt32 LSB first; Bool (one
#  byte 0/1); Byte Array(Var) = one length byte + bytes. Function numbers are
#  from ELATEC's twn4.sys.h (SYSFUNC(API_x, n, ...)).
#
#  ISO 14443-4 APDUs: the reader's own ISO14443_4_TDX can't return a response
#  longer than 255 bytes (its RX is a Byte Array(Var)), which breaks e.g. EMV
#  certificate records. So T=CL is driven in software here, exactly as on the
#  ACR122U/Chameleon back-ends (pynfc._tcl_exchange: block numbers, receive
#  chaining, WTX, CID), carrying each raw frame with ISO14443_3_TDX - which by
#  default adds no CRC, so CRC_A/CRC_B are appended and checked on this side. The
#  system parameter ISO14443_3_TDX_CRCCONTROL can make the firmware do the CRC, so
#  it is forced back to 0 on open. Checked against API Reference DocRev31.

from .pynfc import _tcl_exchange

try:
    import serial
    import serial.tools.list_ports
except ImportError:  # reported when a TWN4 is actually opened
    serial = None

TWN4_VID = 0x09D8  # ELATEC GmbH
TWN4_PID = 0x0420  # TWN4 CDC

# API numbers (twn4.sys.h)
API_SYS = 0x00
API_RF = 0x05
API_ISO14443 = 0x12

# API_SYS functions
SYS_GETVERSIONSTRING = 0x04
SYS_SETPARAMETERS = 0x09
# SetParameters TLV types / values
TLV_END = 0
ISO14443_3_TDX_CRCCONTROL = 34  # 0 = host does CRC; TX 0x02 / RX 0x01 = firmware does
# API_RF functions
RF_SEARCHTAG = 0x00
RF_SETRFOFF = 0x01
RF_SETTAGTYPES = 0x02
RF_GETTAGTYPES = 0x03
# API_ISO14443 functions. Deliberately not used: ISO14443A_GetATS (0) makes the
# TWN4 send its own RATS (FSD 256), and ISO14443_4_TDX (3) / _CheckPresence (2)
# drive T=CL in the reader, which would desync the software T=CL block number.
ISO14443B_GETATQB = 0x01
ISO14443A_GETATQA = 0x04
ISO14443A_GETSAK = 0x05
ISO14443B_GETANSWERTOATTRIB = 0x06
ISO14443_3_TDX = 0x07

# RATS parameter byte: FSDI 7 (FSD 128 bytes) in the high nibble, CID 0
RATS_PARAM = 0x70

# Simple Protocol protocol-level error byte (first byte of every response)
PROTOCOL_ERRORS = {
    0x00: "no error",
    0x01: "unknown function",
    0x02: "missing parameter",
    0x03: "unused parameters",
    0x04: "invalid function",
    0x05: "parser error",
}

# SearchTag tag types (twn4.sys.h)
NOTAG = 0x00
HFTAG_MIFARE = 0x80  # ISO 14443-A / MIFARE
HFTAG_ISO14443B = 0x81
TAG_TYPES = {
    0x40: "EM4x02/CASI-RUSCO",
    0x41: "HITAG 1/HITAG S",
    0x42: "HITAG 2",
    0x43: "EM4x50",
    0x44: "T55x7",
    0x45: "ISO FDX-B",
    0x46: "EM4026",
    0x47: "HITAG U",
    0x48: "EM4305",
    0x49: "HID Prox",
    0x4A: "ISO HDX/TIRIS",
    0x4B: "Cotag",
    0x4C: "ioProx",
    0x4D: "Indala",
    0x4E: "NexWatch",
    0x4F: "AWID",
    0x50: "G-Prox",
    0x51: "Pyramid",
    0x52: "Keri",
    0x53: "Deister",
    0x54: "Cardax",
    0x55: "Nedap",
    0x80: "ISO 14443A/MIFARE",
    0x81: "ISO 14443B",
    0x82: "ISO 15693",
    0x83: "LEGIC",
    0x84: "HID iCLASS",
    0x85: "FeliCa",
    0x86: "SRX",
    0x87: "NFC Peer-to-Peer",
    0x88: "Bluetooth Low Energy",
}


def _crc14443(data, preset, invert):
    "ISO/IEC 14443-3 CRC (CRC_A: preset 0x6363; CRC_B: preset 0xFFFF, inverted), LSB first"
    crc = preset
    for b in data:
        b ^= crc & 0xFF
        b = (b ^ (b << 4)) & 0xFF
        crc = ((crc >> 8) ^ (b << 8) ^ (b << 3) ^ (b >> 4)) & 0xFFFF
    if invert:
        crc ^= 0xFFFF
    return bytes([crc & 0xFF, crc >> 8])


def crc_a(data):
    return _crc14443(data, 0x6363, False)


def crc_b(data):
    return _crc14443(data, 0xFFFF, True)


def tagmask(tagtype):
    "SetTagTypes bit for a SearchTag tag type (twn4.sys.h TAGMASK)"
    return 1 << (tagtype & 0x1F)


class TWN4Error(Exception):
    pass


class TWN4:
    "ELATEC TWN4 reader driver (Simple Protocol, ASCII mode)."

    def __init__(self, port=None, debug=False, timeout=3):
        if serial is None:
            raise TWN4Error("pyserial is required for the TWN4 reader")
        self.debug = debug
        self.port = port or self.find_port()
        if not self.port:
            raise TWN4Error(
                "no TWN4 device found (looked for USB %04x:%04x); "
                "pass the serial port explicitly with -l" % (TWN4_VID, TWN4_PID)
            )
        try:
            # baud rate is ignored by USB CDC; 9600 is the Simple Protocol default
            # for a true serial TWN4
            self.ser = serial.Serial(self.port, 9600, timeout=timeout)
        except Exception as e:
            raise TWN4Error("could not open %s: %s" % (self.port, e))
        self.ser.reset_input_buffer()
        self.version = self.get_version_string()
        if "/PRS" not in self.version:
            raise TWN4Error(
                "%s does not report the Simple Protocol (PRS) app (version '%s') - "
                "load a TWN4 Simple Protocol firmware" % (self.port, self.version)
            )
        self.readername = "ELATEC %s (%s)" % (self.version, self.port)
        # make sure ISO14443_3_TDX leaves the CRC to us (the parameter is
        # runtime state; a False return means firmware without it: CRC is ours)
        self.command(API_SYS, SYS_SETPARAMETERS,
                     bytes([4, ISO14443_3_TDX_CRCCONTROL, 1, 0x00, TLV_END]))
        # software T=CL state for the selected ISO 14443-4 card
        self.ats = ""
        self._iblock = 0
        self._cid = None
        self._crc = crc_a

    # ------------------------------------------------------------------ discovery
    @staticmethod
    def find_port():
        "return the serial device of the first attached TWN4 (USB CDC), or None"
        for p in serial.tools.list_ports.comports():
            if p.vid == TWN4_VID and p.pid == TWN4_PID:
                return p.device
        return None

    # ------------------------------------------------------------------ transport
    def command(self, api, func, params=b"", timeout=None):
        """send one Simple Protocol command, return the response bytes after the error byte.

        `timeout` (seconds) overrides the serial read timeout for a command that
        itself waits on the card (ISO14443_3_TDX), so it can't expire first."""
        line = (bytes([api, func]) + bytes(params)).hex().upper()
        self.ser.reset_input_buffer()
        self.ser.write((line + "\r").encode("ascii"))
        saved = self.ser.timeout
        if timeout is not None:
            self.ser.timeout = timeout
        try:
            resp = self.ser.read_until(b"\r")
        finally:
            self.ser.timeout = saved
        if not resp.endswith(b"\r"):
            raise TWN4Error("timeout waiting for TWN4 response to %s" % line)
        resp = resp.strip().decode("ascii", "replace")
        if self.debug:
            print("  twn4 >> %s  << %s" % (line, resp))
        try:
            data = bytes.fromhex(resp)
        except ValueError:
            raise TWN4Error("malformed TWN4 response '%s'" % resp)
        if not data:
            raise TWN4Error("empty TWN4 response to %s" % line)
        if data[0] != 0x00:
            raise TWN4Error(
                "TWN4 protocol error %d (%s) for %s"
                % (data[0], PROTOCOL_ERRORS.get(data[0], "unknown"), line)
            )
        return data[1:]

    # ------------------------------------------------------------------ device
    def get_version_string(self):
        r = self.command(API_SYS, SYS_GETVERSIONSTRING, b"\xff")
        # [ASCII string] = length byte + characters
        return r[1:1 + r[0]].decode("ascii", "replace") if r else ""

    def get_tag_types(self):
        "return (LF, HF) SearchTag tag-type masks"
        r = self.command(API_RF, RF_GETTAGTYPES)
        return int.from_bytes(r[0:4], "little"), int.from_bytes(r[4:8], "little")

    def set_tag_types(self, lf, hf):
        self.command(API_RF, RF_SETTAGTYPES, lf.to_bytes(4, "little") + hf.to_bytes(4, "little"))

    def rf_off(self):
        self.command(API_RF, RF_SETRFOFF)

    # ------------------------------------------------------------------ tags
    def search_tag(self, maxidbytes=0x10):
        "SearchTag: return (tagtype, idbitcount, id_hex) or None if no tag"
        r = self.command(API_RF, RF_SEARCHTAG, bytes([maxidbytes]))
        if not r or not r[0]:
            return None
        tagtype, bitcount, idlen = r[1], r[2], r[3]
        return tagtype, bitcount, r[4:4 + idlen].hex().upper()

    def select(self, tagtype):
        """search for one tag of the given HF type (HFTAG_MIFARE / HFTAG_ISO14443B).

        Narrows SearchTag to that type only (no LF, no other HF), so another tag
        in the field can't be returned instead, then restores the reader's tag
        types at once - the TWN4 keeps them until reset, so they must not leak to
        a later process (tools often exit without calling shutdown()).

        For an ISO 14443-4 Type A card (SAK bit 0x20) it then sends RATS itself:
        SearchTag stops at ISO 14443-3 (the TWN4 only sends RATS when asked for
        the ATS), and the TWN4's own RATS announces FSD 256, so a card's chained
        frames could exceed the 255 bytes ISO14443_3_TDX can return (e.g. EMV
        certificate records). RATS_PARAM asks for FSD 128 instead; the ATS (with
        its TL byte) is kept in self.ats. Returns (id_hex, bitcount) or None.
        """
        saved = self.get_tag_types()
        try:
            self.set_tag_types(0, tagmask(tagtype))
            tag = self.search_tag()
        finally:
            self.set_tag_types(*saved)
        if tag is None or tag[0] != tagtype:
            return None
        # fresh T=CL state for the newly activated card
        self._iblock = 0
        self._cid = None
        self._crc = crc_a if tagtype == HFTAG_MIFARE else crc_b
        self.ats = ""
        if tagtype == HFTAG_MIFARE:
            sak = self.get_sak()
            if sak and int(sak, 16) & 0x20:
                ok, ats = self._raw_frame("E0%02X" % RATS_PARAM)
                if ok:
                    self.ats = ats
        if tagtype == HFTAG_ISO14443B:
            # the CID assigned by the reader's ATTRIB is the low nibble of the
            # answer to ATTRIB; a card given a non-zero CID needs it in every block
            ans = self._bool_array(ISO14443B_GETANSWERTOATTRIB, b"\xff")
            if ans and ans[0] & 0x0F:
                self._cid = ans[0] & 0x0F
        return tag[2], tag[1]

    def _bool_array(self, func, params=b"", fixed=None):
        "call an ISO14443 function returning [Bool][Byte Array(fixed or Var)]"
        r = self.command(API_ISO14443, func, params)
        if not r or not r[0]:
            return None
        if fixed is not None:
            return r[1:1 + fixed]
        return r[2:2 + r[1]]

    def get_atqa(self):
        "ATQA as conventionally written (MSB first, e.g. '0044'); the reader sends it LSB first"
        a = self._bool_array(ISO14443A_GETATQA, fixed=2)
        return a[::-1].hex().upper() if a else ""

    def get_sak(self):
        s = self._bool_array(ISO14443A_GETSAK, fixed=1)
        return s.hex().upper() if s else ""

    def get_atqb(self):
        a = self._bool_array(ISO14443B_GETATQB, b"\xff")
        return a.hex().upper() if a else ""

    def _raw_frame(self, frame_hex, timeout=None):
        "one raw ISO 14443-3 frame via ISO14443_3_TDX: (True, reply_hex sans CRC) or (False, -1)"
        tx = bytes.fromhex(frame_hex)
        tx += self._crc(tx)
        if len(tx) > 0xFF:
            return False, -1
        # per-frame response timeout (ms); a slow card asks for more with S(WTX)
        ms = 3000 if timeout is None else max(int(timeout * 1000), 1000)
        ms = min(ms, 0xFFFF)
        r = self.command(API_ISO14443, ISO14443_3_TDX,
                         bytes([len(tx)]) + tx + b"\xff" + ms.to_bytes(2, "little"),
                         timeout=ms / 1000 + 1)
        if not r or not r[0] or len(r) < 2:
            return False, -1
        rx = r[2:2 + r[1]]
        if len(rx) < 3 or self._crc(rx[:-2]) != rx[-2:]:
            if self.debug:
                print("  twn4: bad/short frame %s" % rx.hex())
            return False, -1
        return True, rx[:-2].hex().upper()

    def sendAPDU(self, apdu, timeout=None):
        """ISO 14443-4 APDU transceive: return (True, response_hex incl. SW1SW2) or (False, -1).

        `apdu` is a hex string (or a list of hex strings). T=CL runs in software
        (see the header), so responses of any length come back, in chained frames.
        """
        apdu = "".join(list(apdu)).upper()
        try:
            ok, resp, self._iblock = _tcl_exchange(
                self._raw_frame, apdu, self._iblock, timeout, None, self._cid
            )
        except TWN4Error:
            return False, -1
        return ok, resp

    # ------------------------------------------------------------------ lifecycle
    def close(self):
        try:
            self.rf_off()
        except Exception:
            pass
        try:
            self.ser.close()
        except Exception:
            pass
