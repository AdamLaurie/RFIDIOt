#  pychameleon.py - minimal pyserial driver for the Proxgrind/RRG Chameleon Ultra
#  used as a 13.56 MHz ISO/IEC 14443-A reader by RFIDIOt (READER_CHAMELEON).
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
#  Protocol (RfidResearchGroup/ChameleonUltra, verified on hw_v1 / fw v2.2.0):
#    USB CDC-ACM serial @ 115200. Binary frame, all multi-byte fields big-endian:
#      SOF(1)=0x11 | LRC1(1) over SOF | CMD(2) | STATUS(2) | LEN(2) |
#      LRC2(1) over SOF..LEN | DATA(LEN) | LRC3(1) over SOF..DATA
#    where LRC = (0x100 - (sum(preceding bytes) & 0xFF)) & 0xFF.
#
#  Reader recipe (firmware has no single-call 14443-4 APDU command in a release
#  yet): HF14A_SCAN_KEEP selects + does RATS and keeps the field alive; each APDU
#  is then an HF14A_RAW transceive wrapped in the ISO 14443-4 (T=CL) block
#  protocol in software here - I-block block-number toggling, S(WTX) waiting-time
#  extension replies, and receive-side chaining for long responses (e.g. DG2).

import struct
import time

try:
    import serial
    import serial.tools.list_ports
except ImportError:
    serial = None

# --- command IDs (subset we use) ---
CMD_GET_APP_VERSION = 1000
CMD_CHANGE_DEVICE_MODE = 1001
CMD_GET_DEVICE_MODE = 1002
CMD_HF14A_SCAN = 2000
CMD_HF14A_RAW = 2010
CMD_HF14A_SCAN_KEEP = 2016

# --- device status codes ---
STATUS_HF_TAG_OK = 0x0000
STATUS_HF_TAG_NO = 0x0001
STATUS_DEVICE_SUCCESS = 0x0068
STATUS_INVALID_CMD = 0x0067

# --- HF14A_RAW option bits (MSB first) ---
OPT_ACTIVATE_RF = 0x80
OPT_WAIT_RESP = 0x40
OPT_APPEND_CRC = 0x20
OPT_AUTO_SELECT = 0x10
OPT_KEEP_FIELD = 0x08
OPT_CHECK_CRC = 0x04

# USB identity (application mode)
CHAMELEON_VID = 0x6868  # Proxgrind
CHAMELEON_PID = 0x8686

# minimum firmware: HF14A_SCAN_KEEP + HF14A_RAW exist from the v2.x line; older
# builds return STATUS_INVALID_CMD for the reader commands.
MIN_FW_MAJOR = 2


class ChameleonError(Exception):
    pass


class Chameleon:
    "Chameleon Ultra reader driver (ISO 14443-A + ISO 14443-4 APDU transceive)."

    def __init__(self, port=None, debug=False, timeout=5):
        if serial is None:
            raise ChameleonError("pyserial is required for the Chameleon reader")
        self.debug = debug
        self.port = port or self.find_port()
        if not self.port:
            raise ChameleonError(
                "no Chameleon device found (looked for USB %04x:%04x); "
                "pass the serial port explicitly with -l" % (CHAMELEON_VID, CHAMELEON_PID)
            )
        try:
            self.ser = serial.Serial(self.port, 115200, timeout=timeout)
        except Exception as e:
            raise ChameleonError("could not open %s: %s" % (self.port, e))
        self._iblock = 0  # ISO 14443-4 I-block number
        self.readername = "Chameleon Ultra (%s)" % self.port
        self._check_firmware()

    # ------------------------------------------------------------------ discovery
    @staticmethod
    def find_port():
        "return the serial device of the first attached Chameleon, or None"
        for p in serial.tools.list_ports.comports():
            if p.vid == CHAMELEON_VID and p.pid == CHAMELEON_PID:
                return p.device
        return None

    # ------------------------------------------------------------------ framing
    @staticmethod
    def _lrc(data):
        return (0x100 - (sum(data) & 0xFF)) & 0xFF

    def _make_frame(self, cmd, data=b""):
        f = bytes([0x11])
        f += bytes([self._lrc(f)])  # LRC1 over SOF
        f += struct.pack("!HHH", cmd, 0, len(data))
        f += bytes([self._lrc(f)])  # LRC2 over SOF..LEN
        f += data
        f += bytes([self._lrc(f)])  # LRC3 over SOF..DATA
        return f

    def _read_frame(self):
        ser = self.ser
        while True:
            b = ser.read(1)
            if not b:
                raise ChameleonError("timeout waiting for Chameleon response")
            if b == b"\x11":
                break
        head = b + ser.read(8)
        if len(head) != 9:
            raise ChameleonError("short Chameleon response header")
        _, lrc1, cmd, status, length, lrc2 = struct.unpack("!BBHHHB", head)
        if self._lrc(head[:1]) != lrc1 or self._lrc(head[:8]) != lrc2:
            raise ChameleonError("bad Chameleon response header checksum")
        rest = ser.read(length + 1)
        if len(rest) != length + 1:
            raise ChameleonError("short Chameleon response body")
        data, lrc3 = rest[:length], rest[length]
        if self._lrc(head + data) != lrc3:
            raise ChameleonError("bad Chameleon response data checksum")
        return cmd, status, data

    def command(self, cmd, data=b""):
        "send a command frame and return (status, response_data_bytes)"
        self.ser.reset_input_buffer()
        self.ser.write(self._make_frame(cmd, data))
        _, status, rdata = self._read_frame()
        if self.debug:
            print("  chameleon cmd %d -> status 0x%04x data %s"
                  % (cmd, status, rdata.hex()))
        return status, rdata

    # ------------------------------------------------------------------ device
    def app_version(self):
        "return (major, minor) firmware version"
        status, data = self.command(CMD_GET_APP_VERSION)
        if len(data) >= 2:
            return data[0], data[1]
        return 0, 0

    def _check_firmware(self):
        major, minor = self.app_version()
        self.fw_version = "%d.%d" % (major, minor)
        if major < MIN_FW_MAJOR:
            raise ChameleonError(
                "Chameleon firmware v%s is too old for reader use (needs the modern "
                "command set, v%d.x+). Update it with the RfidResearchGroup "
                "ChameleonUltra release (ultra-dfu-app.zip)." % (self.fw_version, MIN_FW_MAJOR)
            )

    def set_reader_mode(self):
        "switch the device into reader (initiator) mode"
        status, _ = self.command(CMD_CHANGE_DEVICE_MODE, b"\x01")
        if status not in (STATUS_DEVICE_SUCCESS, STATUS_HF_TAG_OK):
            raise ChameleonError("could not set reader mode (status 0x%04x)" % status)

    # ------------------------------------------------------------------ 14443-A
    def scan(self):
        """select + RATS a single ISO 14443-A tag, keeping the field alive.

        Returns (uid, atqa, sak, ats) as uppercase hex strings, or None if no tag.
        """
        status, d = self.command(CMD_HF14A_SCAN_KEEP)
        if status != STATUS_HF_TAG_OK or len(d) < 4:
            return None
        uidlen = d[0]
        uid = d[1:1 + uidlen]
        atqa = d[1 + uidlen:3 + uidlen]
        sak = d[3 + uidlen:4 + uidlen]
        atslen = d[4 + uidlen] if len(d) > 4 + uidlen else 0
        ats = d[5 + uidlen:5 + uidlen + atslen]
        self._iblock = 0  # reset T=CL block number for the new activation
        return uid.hex().upper(), atqa.hex().upper(), sak.hex().upper(), ats.hex().upper()

    # ------------------------------------------------------------------ T=CL APDU
    def _raw(self, options, data=b"", timeout_ms=2000):
        payload = bytes([options]) + struct.pack("!HH", timeout_ms, len(data) * 8) + data
        return self.command(CMD_HF14A_RAW, payload, )

    def _transceive_block(self, block, timeout_ms):
        "send one raw 14443-4 block (CRC appended/checked by firmware), return INF+PCB bytes"
        status, resp = self._raw(
            OPT_WAIT_RESP | OPT_APPEND_CRC | OPT_CHECK_CRC | OPT_KEEP_FIELD,
            block, timeout_ms,
        )
        if status != STATUS_HF_TAG_OK:
            raise ChameleonError("14443-4 transceive failed (status 0x%04x)" % status)
        if not resp:
            raise ChameleonError("empty 14443-4 response")
        return resp

    def sendAPDU(self, apdu, timeout=3):
        """Send one ISO 14443-4 APDU (hex string) and return (True, response_hex).

        response_hex is the card's APDU response (data + SW1 SW2), uppercase, with
        the T=CL block protocol (PCB/CRC/WTX/chaining) handled here. Mirrors the
        libnfc path's (ok, hex) return so the rfidiot class can treat them alike.
        """
        timeout_ms = int(timeout * 1000)
        apdu_bytes = bytes.fromhex(apdu)

        # send as a single I-block (command APDUs fit a frame; send-side chaining
        # is not needed for the eMRTD/EMV read flows)
        pcb = 0x02 | self._iblock
        resp = self._transceive_block(bytes([pcb]) + apdu_bytes, timeout_ms)

        inf = bytearray()
        guard = 0
        while True:
            guard += 1
            if guard > 4096:
                raise ChameleonError("14443-4 chaining did not terminate")
            p = resp[0]
            if (p & 0xC0) == 0x00:
                # I-block: collect INF, handle receive chaining
                inf += resp[1:]
                if p & 0x10:
                    # card is chaining - send R(ACK) with the *toggled* block
                    # number so the PICC advances to the next block (ISO 14443-4
                    # rule 10/11); acking with the same number stalls the chain
                    ack = 0xA2 | ((p & 0x01) ^ 0x01)
                    resp = self._transceive_block(bytes([ack]), timeout_ms)
                    continue
                # final I-block: the next command's block number is this block's
                # number toggled. Deriving it from the last received block (rather
                # than a blind per-APDU toggle) keeps us in sync when the card
                # chained an odd number of blocks - otherwise the next command is
                # sent with the wrong block number and the card ignores it.
                self._iblock = (p & 0x01) ^ 0x01
                break
            if (p & 0xF6) == 0xF2:
                # S(WTX) waiting-time extension request: echo it back
                resp = self._transceive_block(bytes([0xF2, resp[1]]), timeout_ms)
                continue
            raise ChameleonError("unexpected 14443-4 PCB 0x%02x" % p)

        return True, bytes(inf).hex().upper()

    # ------------------------------------------------------------------ lifecycle
    def close(self):
        try:
            self.ser.close()
        except Exception:
            pass
