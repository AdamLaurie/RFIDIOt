#!/usr/bin/python

#
# pynfc.py - Python wrapper for libnfc
# version 0.2 (should work with libnfc 1.2.1 and 1.3.0)
# version 0.2a - tweaked by rfidiot for libnfc 1.6.0-rc1 october 2012
# Nick von Dadelszen (nick@lateralsecurity.com)
# Lateral Security (www.lateralsecurity.com)

#  Thanks to metlstorm for python help :)
#
# This code is copyright (c) Nick von Dadelszen, 2009, All rights reserved.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

# pylint: disable=too-many-instance-attributes,too-few-public-methods,too-few-public-methods,attribute-defined-outside-init
# pylint: disable=logging-not-lazy,logging-fstring-interpolation

import sys
import ctypes
import ctypes.util
# import binascii
import logging
# import time
# import readline

# import string
from . import rfidiotglobals

# nfc_property enumeration
NP_TIMEOUT_COMMAND = 0x00
NP_TIMEOUT_ATR = 0x01
NP_TIMEOUT_COM = 0x02
NP_HANDLE_CRC = 0x03
NP_HANDLE_PARITY = 0x04
NP_ACTIVATE_FIELD = 0x05
NP_ACTIVATE_CRYPTO1 = 0x06
NP_INFINITE_SELECT = 0x07
NP_ACCEPT_INVALID_FRAMES = 0x08
NP_ACCEPT_MULTIPLE_FRAMES = 0x09
NP_AUTO_ISO14443_4 = 0x0A
NP_EASY_FRAMING = 0x0B
NP_FORCE_ISO14443_A = 0x0C
NP_FORCE_ISO14443_B = 0x0D
NP_FORCE_SPEED_106 = 0x0E

# NFC modulation type enumeration
NMT_ISO14443A = 0x01
NMT_JEWEL = 0x02
NMT_ISO14443B = 0x03
NMT_ISO14443BI = 0x04
NMT_ISO14443B2SR = 0x05
NMT_ISO14443B2CT = 0x06
NMT_FELICA = 0x07
NMT_DEP = 0x08
NMT_BARCODE = 0x09
NMT_ISO14443BICLASS = 0x0A
NMT_END_ENUM = NMT_ISO14443BICLASS  # dummy for sizing - always should alias last

# NFC baud rate enumeration
NBR_UNDEFINED = 0x00
NBR_106 = 0x01
NBR_212 = 0x02
NBR_424 = 0x03
NBR_847 = 0x04

# NFC D.E.P. (Data Exchange Protocol) active/passive mode
NDM_UNDEFINED = 0x00
NDM_PASSIVE = 0x01
NDM_ACTIVE = 0x02

# Mifare commands
MC_AUTH_A = 0x60
MC_AUTH_B = 0x61
MC_READ = 0x30
MC_WRITE = 0xA0
MC_TRANSFER = 0xB0
MC_DECREMENT = 0xC0
MC_INCREMENT = 0xC1
MC_STORE = 0xC2

# PN53x specific errors */
ETIMEOUT = 0x01
ECRC = 0x02
EPARITY = 0x03
EBITCOUNT = 0x04
EFRAMING = 0x05
EBITCOLL = 0x06
ESMALLBUF = 0x07
EBUFOVF = 0x09
ERFTIMEOUT = 0x0A
ERFPROTO = 0x0B
EOVHEAT = 0x0D
EINBUFOVF = 0x0E
EINVPARAM = 0x10
EDEPUNKCMD = 0x12
EINVRXFRAM = 0x13
EMFAUTH = 0x14
ENSECNOTSUPP = 0x18  # PN533 only
EBCC = 0x23
EDEPINVSTATE = 0x25
EOPNOTALL = 0x26
ECMD = 0x27
ETGREL = 0x29
ECID = 0x2A
ECDISCARDED = 0x2B
ENFCID3 = 0x2C
EOVCURRENT = 0x2D
ENAD = 0x2E

MAX_FRAME_LEN = 264
MAX_DEVICES = 16
BUFSIZ = 8192
MAX_TARGET_COUNT = 1

DEVICE_NAME_LENGTH = 256
DEVICE_PORT_LENGTH = 64
NFC_CONNSTRING_LENGTH = 1024

# NFC Return Error Codes
# /usr/include/nfc/nfc.h
NFC_SUCCESS = 0
NFC_EIO = -1
NFC_EINVARG = -2
NFC_EDEVNOTSUPP = -3
NFC_ENOTSUCHDEV = -4
NFC_EOVFLOW = -5
NFC_ETIMEOUT = -6
NFC_EOPABORTED = -7
NFC_ENOTIMPL = -8
NFC_ETGRELEASED = -10
NFC_ERFTRANS = -20
NFC_EMFCAUTHFAIL = -30
NFC_ESOFT = -80
NFC_ECHIP = -90

NFC_LIB_ERROR_CODES = {
    0: "NFC_SUCCESS, Success (no error)",
    -1: "NFC_EIO, Input / output error",
    -2: "NFC_EINVARG Invalid argument(s)",
    -3: "NFC_EDEVNOTSUPP Operation not supported by device",
    -4: "NFC_ENOTSUCHDEV No such device",
    -5: "NFC_EOVFLOW, Buffer overflow",
    -6: "NFC_ETIMEOUT, Operation timed out",
    -7: "NFC_EOPABORTED, Operation aborted (by user)",
    -8: "NFC_ENOTIMPL, Not (yet) implemented",
    -10: "NFC_ETGRELEASED, Target released",
    -20: "NFC_ERFTRANS, Error while RF transmission",
    -30: "NFC_EMFCAUTHFAIL, MIFARE Classic: authentication failed",
    -80: "NFC_ESOFT Software error",
    -90: "NFC_ECHIP internal chip error",
}


class NFC_DEP_INFO(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("abtNFCID3", ctypes.c_ubyte * 10),
        ("btDID", ctypes.c_ubyte),
        ("btBS", ctypes.c_ubyte),
        ("btBR", ctypes.c_ubyte),
        ("btTO", ctypes.c_ubyte),
        ("btPP", ctypes.c_ubyte),
        ("abtGB", ctypes.c_ubyte * 48),
        ("szGB", ctypes.c_size_t),
        ("ndm", ctypes.c_ubyte),
    ]


class NFC_ISO14443A_INFO(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("abtAtqa", ctypes.c_ubyte * 2),
        ("btSak", ctypes.c_ubyte),
        ("uiUidLen", ctypes.c_size_t),
        ("abtUid", ctypes.c_ubyte * 10),
        ("uiAtsLen", ctypes.c_size_t),
        ("abtAts", ctypes.c_ubyte * 254),
    ]


class NFC_FELICA_INFO(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("szLen", ctypes.c_size_t),
        ("btResCode", ctypes.c_ubyte),
        ("abtId", ctypes.c_ubyte * 8),
        ("abtPad", ctypes.c_ubyte * 8),
        ("abtSysCode", ctypes.c_ubyte * 2),
    ]


class NFC_ISO14443B_INFO(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("abtPupi", ctypes.c_ubyte * 4),
        ("abtApplicationData", ctypes.c_ubyte * 4),
        ("abtProtocolInfo", ctypes.c_ubyte * 3),
        ("ui8CardIdentifier", ctypes.c_ubyte),
    ]


class NFC_ISO14443BI_INFO(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("abtDIV", ctypes.c_ubyte * 4),
        ("btVerLog", ctypes.c_ubyte),
        ("btConfig", ctypes.c_ubyte),
        ("szAtrLen", ctypes.c_size_t),
        ("abtAtr", ctypes.c_ubyte * 33),
    ]


class NFC_ISO14443BICLASS_INFO(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("abtUID", ctypes.c_ubyte * 8)]


class NFC_ISO14443B2SR_INFO(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("abtUID", ctypes.c_ubyte * 8)]


class NFC_ISO14443B2CT_INFO(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("abtUID", ctypes.c_ubyte * 4),
        ("btProdCode", ctypes.c_ubyte),
        ("btFabCode", ctypes.c_ubyte),
    ]


class NFC_JEWEL_INFO(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("btSensRes", ctypes.c_ubyte * 2), ("btId", ctypes.c_ubyte * 4)]


class NFC_BARCODE_INFO(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("szDataLen", ctypes.c_size_t), ("abtData", ctypes.c_ubyte * 32)]


class NFC_TARGET_INFO(ctypes.Union):
    _pack_ = 1
    _fields_ = [
        ("nai", NFC_ISO14443A_INFO),
        ("nfi", NFC_FELICA_INFO),
        ("nbi", NFC_ISO14443B_INFO),
        ("nii", NFC_ISO14443BI_INFO),
        ("nic", NFC_ISO14443BICLASS_INFO),
        ("nsi", NFC_ISO14443B2SR_INFO),
        ("nci", NFC_ISO14443B2CT_INFO),
        ("nji", NFC_JEWEL_INFO),
        ("nti", NFC_BARCODE_INFO),
        ("ndi", NFC_DEP_INFO),
    ]


class NFC_CONNSTRING(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("connstring", ctypes.c_ubyte * NFC_CONNSTRING_LENGTH)]


class NFC_MODULATION(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("nmt", ctypes.c_uint), ("nbr", ctypes.c_uint)]


class NFC_TARGET(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("nti", NFC_TARGET_INFO), ("nm", NFC_MODULATION)]


# class NFC_DEVICE(ctypes.Structure):
#       _fields_ = [('driver', ctypes.pointer(NFC_DRIVER),
#                   ('driver_data', ctypes.c_void_p),
#                   ('chip_data', ctypes.c_void_p),
#                   ('name', ctypes.c_ubyte * DEVICE_NAME_LENGTH),
#                   ('nfc_connstring', ctypes.c_ubyte * NFC_CONNSTRING_LENGTH),
#                   ('bCrc', ctypes.c_bool),
#                   ('bPar', ctypes.c_bool),
#                   ('bEasyFraming', ctypes.c_bool),
#                   ('bAutoIso14443_4', ctypes.c_bool),
#                   ('btSupportByte', ctypes.c_ubyte).
#                   ('last_error', ctypes.c_byte)]

# class NFC_DEVICE_DESC_T(ctypes.Structure):
#       _fields_ = [('acDevice',ctypes.c_char * BUFSIZ),
#                   ('pcDriver',ctypes.c_char_p),
#                   ('pcPort',ctypes.c_char_p),
#                   ('uiSpeed',ctypes.c_ulong),
#                   ('uiBusIndex',ctypes.c_ulong)]

# NFC_DEVICE_LIST = NFC_DEVICE_DESC_T * MAX_DEVICES
NFC_DEVICE_LIST = NFC_CONNSTRING * MAX_DEVICES


class ISO14443A():
    def __init__(self, ti):
        self.uid = "".join([f"{x:02X}" for x in ti.abtUid[: ti.uiUidLen]])
        if ti.uiAtsLen:
            self.atr = "".join([f"{x:02X}" for x in ti.abtAts[: ti.uiAtsLen]])
        else:
            self.atr = ""
        self.atqa = "".join([f"{x:02X}" for x in ti.abtAtqa])
        self.sak = f"{ti.btSak:02X}"

    def __str__(self):
        rv = "ISO14443A(uid='{0.uid}', atr='{0.atr}', atqa='{0.atqa}', sak='{0.sak}')".format(self)
        # rv = "ISO14443A(uid='%s', atr='%s', atqa='%s', sak='%s')" % (
        #     self.uid,
        #     self.atr,
        #     self.atqa,
        #     self.sak,
       #  )

        return rv


class ISO14443B():
    def __init__(self, ti):
        self.pupi = "".join([f"{x:02X}" for x in ti.abtPupi[:4]])
        self.uid = self.pupi  # for sake of compatibility with apps written for typeA
        self.appdata = "".join([f"{x:02X}" for x in ti.abtApplicationData[:4]])
        self.protocol = "".join([f"{x:02X}" for x in ti.abtProtocolInfo[:3]])
        self.cid = "%02x" % ti.ui8CardIdentifier
        self.atr = ""  # idem

    def __str__(self):
        rv = f"ISO14443B(pupi='{self.pupi}')"
        return rv


class ICLASS():
    def __init__(self, ti):
        self.uid = "".join([f"{x:02X}" for x in ti.abtUID])

    def __str__(self):
        rv = "ICLASS(uid='self.uid')"
        return rv


class JEWEL():
    def __init__(self, ti):
        self.btSensRes = "".join([f"{x:02X}" for x in ti.btSensRes[:2]])
        self.btId = "".join([f"{x:02X}" for x in ti.btId[:4]])
        self.uid = self.btId
        self.atr = ""  # idem
        self.atqa = self.btSensRes
        self.sak = ""

    def __str__(self):
        rv = "JEWEL(btSensRes='%s', btId='%s')" % (self.btSensRes, self.btId)
        return rv


def _tcl_exchange(raw_frame, apdu, iblock, timeout=None, log=None):
    """Drive one ISO 7816 APDU over the ISO 14443-4 (T=CL) block protocol.

    `raw_frame(hexframe, timeout) -> (ok, hex)` sends exactly one T=CL frame and
    returns the card's one-frame reply (CRC already stripped by the reader). We
    own the PCB here, so we toggle the I-block number, answer the card's receive-
    side chaining with R(ACK)s, and echo S(WTX) waiting-time-extension requests.
    The command APDU is sent as a single I-block (the eMRTD/EMV read flows never
    need send-side chaining); only the response may be chained. Returns
    (ok, hex_or_errcode, next_iblock); on error `iblock` is returned unchanged.

    Shared by both raw-frame backends - the libnfc one (NFC, easy framing off)
    and the direct-CCID one (ACR122CCID, PN532 InCommunicateThru) - so the T=CL
    engine lives in exactly one place.
    """
    pcb = 0x02 | iblock
    ok, resp = raw_frame("%02X%s" % (pcb, apdu), timeout)
    if not ok:
        return False, resp, iblock
    inf = ""
    guard = 0
    while True:
        guard += 1
        if guard > 4096:
            if log:
                log.error("T=CL chaining did not terminate")
            return False, -1, iblock
        if len(resp) < 2:
            return False, -1, iblock
        p = int(resp[0:2], 16)
        if (p & 0xC0) == 0x00:
            # I-block: collect INF; if the card is chaining, R(ACK) with the
            # *toggled* block number so it advances to the next block
            inf += resp[2:]
            if p & 0x10:
                ok, resp = raw_frame("%02X" % (0xA2 | ((p & 1) ^ 1)), timeout)
                if not ok:
                    return False, resp, iblock
                continue
            # final I-block: next command's block number is this one toggled
            iblock = (p & 1) ^ 1
            break
        if (p & 0xF6) == 0xF2:
            # S(WTX) waiting-time extension request: echo the INF byte back
            ok, resp = raw_frame("F2" + resp[2:4], timeout)
            if not ok:
                return False, resp, iblock
            continue
        if log:
            log.error("unexpected T=CL PCB 0x%s" % resp[0:2])
        return False, -1, iblock
    return True, inf.upper(), iblock


class _ISODEP():
    """ISO 14443-4 APDU dispatch shared by the raw-frame backends.

    A host class must provide: self._raw_frame(hexframe, timeout) -> (ok, hex)
    (one T=CL frame), self._plain_apdu(apdu, timeout) -> (ok, hex) (the non-T=CL
    path), and the attributes self.software_tcl, self._iblock and self.log.
    """

    def sendAPDU(self, apdu, timeout=None):
        apdu = "".join(list(apdu))
        if self.software_tcl:
            return self._sendAPDU_tcl(apdu, timeout)
        return self._plain_apdu(apdu, timeout)

    def _sendAPDU_tcl(self, apdu, timeout=None):
        "send one APDU wrapped in software-driven T=CL (see _tcl_exchange)"
        log = self.log if rfidiotglobals.Debug else None
        ok, resp, self._iblock = _tcl_exchange(
            self._raw_frame, apdu, self._iblock, timeout, log
        )
        return ok, resp


class NFC(_ISODEP):
    tag = (NFC_TARGET * MAX_TARGET_COUNT)()

    def __init__(self, nfcreader=None, listonly=False):
        self.LIB = ctypes.util.find_library("nfc")
        self.device = None
        self.context = ctypes.POINTER(ctypes.c_int)()
        self.poweredUp = False
        self.NFCReader = nfcreader
        # ISO 14443-4 (T=CL) driven in software rather than by the reader firmware
        # (see enable_software_tcl() / the ACR122U workaround in sendAPDU).
        self.software_tcl = False
        self._iblock = 0
        self.is_acr122 = False
        self.LIBNFC_CONNSTRING = ""

        self.initLog()
        self.LIBNFC_VER = self.initlibnfc().decode("utf-8")
        if rfidiotglobals.Debug:
            self.log.debug(f"libnfc {self.LIBNFC_VER}")
        # listonly is used by the '-N' device enumeration: opening a device here
        # would make nfc_list_devices' intrusive probe fail with EBUSY, so skip
        # configure() and leave the device closed.
        if not listonly:
            self.configure(nfcreader)
        sys.stdout.flush()

    def __del__(self):
        self.deconfigure()

    def initLog(self, level=logging.DEBUG):
        #       def initLog(self, level=logging.INFO):
        self.log = logging.getLogger("pynfc")
        self.log.setLevel(level)
        sh = logging.StreamHandler()
        sh.setLevel(level)
        f = logging.Formatter("%(asctime)s: %(levelname)s - %(message)s")
        sh.setFormatter(f)
        self.log.addHandler(sh)

    def initlibnfc(self):
        if rfidiotglobals.Debug:
            self.log.debug(f"Loading {self.LIB}")
        self.libnfc = ctypes.CDLL(self.LIB)
        self.libnfc.nfc_version.restype = ctypes.c_char_p
        self.libnfc.nfc_device_get_name.restype = ctypes.c_char_p
        self.libnfc.nfc_device_get_name.argtypes = [ctypes.c_void_p]
        self.libnfc.nfc_device_get_connstring.restype = ctypes.c_char_p
        self.libnfc.nfc_device_get_connstring.argtypes = [ctypes.c_void_p]
        self.libnfc.nfc_open.restype = ctypes.c_void_p
        self.libnfc.nfc_initiator_init.argtypes = [ctypes.c_void_p]
        self.libnfc.nfc_device_set_property_bool.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_bool,
        ]
        self.libnfc.nfc_device_set_property_int.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_int,
        ]
        self.libnfc.nfc_close.argtypes = [ctypes.c_void_p]
        self.libnfc.nfc_perror.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
        self.libnfc.nfc_initiator_list_passive_targets.argtypes = [
            ctypes.c_void_p,
            ctypes.Structure,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        self.libnfc.nfc_initiator_transceive_bytes.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_uint32,
        ]
        self.libnfc.nfc_initiator_target_is_present.argtypes = [
            ctypes.c_void_p,
            ctypes.Structure,
        ]
        self.libnfc.nfc_init(ctypes.byref(self.context))
        return self.libnfc.nfc_version()

    def listreaders(self, target):
        devices = NFC_DEVICE_LIST()
        nfc_num_devices = ctypes.c_size_t()
        nfc_num_devices = self.libnfc.nfc_list_devices(
            self.context, ctypes.byref(devices), MAX_DEVICES
        )
        if not target is None:
            if target > nfc_num_devices - 1:
                print(f"Reader number {target} not found!")
                return None
            return devices[target]
        print(
            "LibNFC ver", self.libnfc.nfc_version().decode("utf-8"), "devices (%d):" % nfc_num_devices
        )
        if nfc_num_devices == 0:
            print("\t", "no supported devices!")
            return None   # ???  Missing return VAl
        for i in range(nfc_num_devices):
            if devices[i]:
                self.log.debug(
                    "nfc_open: %s"
                    % ctypes.cast(devices[i].connstring, ctypes.c_char_p).value
                )
                dev = self.libnfc.nfc_open(self.context, ctypes.byref(devices[i]))
                devname = self.libnfc.nfc_device_get_name(dev).decode("utf-8")
                print(f"    No: {i}\t\t{devname}")
                self.libnfc.nfc_close(dev)
                # print '    No: %d\t\t%s (%s)' % (i,devname,devices[i].acDevice)
                # print '    \t\t\t\tDriver:',devices[i].pcDriver
                # if devices[i].pcPort != None:
                #       print '    \t\t\t\tPort:', devices[i].pcPort
                #       print '    \t\t\t\tSpeed:', devices[i].uiSpeed
        return None   # ???  Missing return VAl

    def configure(self, nfcreader):
        if isinstance(nfcreader, str):
            # nfcreader is a libnfc connstring, e.g. "pn53x_usb" (driver only -
            # opens the first such device) or a full "pn53x_usb:003:087". Open it
            # directly. This deliberately skips nfc_list_devices, whose intrusive
            # probe opens - and so grabs - every other reader, including acr122
            # devices that may be in use at the same time via PC/SC.
            cs = ctypes.create_string_buffer(nfcreader.encode("ascii"), NFC_CONNSTRING_LENGTH)
            self.device = self.libnfc.nfc_open(self.context, cs)
        else:
            if rfidiotglobals.Debug:
                self.log.debug("NFC Readers:")
                self.listreaders(None)
                self.log.debug(
                    "Connecting to NFC reader number: %s" % repr(nfcreader)
                )  # nfcreader may be none
            if not nfcreader is None:
                target = self.listreaders(nfcreader)
            else:
                target = None
            if target:
                target = ctypes.byref(target)
            self.device = self.libnfc.nfc_open(self.context, target)

        if self.device is None:
            raise ConnectionAbortedError("Error opening NFC reader")
        # else:
        # Segmentation fault if self.device is None *pnd->nam
        self.LIBNFC_READER = self.libnfc.nfc_device_get_name(self.device).decode("utf-8")
        # The ACR122U's PN532 reassembles ISO 14443-4 (T=CL) chained responses in
        # a small internal buffer and overflows on long records (e.g. EMV issuer-
        # public-key-certificate records, ePassport DG2), aborting the transceive
        # with pseudo status "63 27". The reader name is generic ("CCID USB
        # Reader"), so detect it by its libnfc connstring driver prefix ("acr122")
        # and, for 14443-4 cards, drive T=CL in software (see sendAPDU) so each
        # I-block stays within a single frame.
        try:
            cs = self.libnfc.nfc_device_get_connstring(self.device)
            self.LIBNFC_CONNSTRING = cs.decode("utf-8", "replace") if cs else ""
        except Exception:
            self.LIBNFC_CONNSTRING = ""
        self.is_acr122 = self.LIBNFC_CONNSTRING.lower().startswith("acr122")

        if rfidiotglobals.Debug:
            # if self.device == None:
            #     self.log.error("Error opening NFC reader")
            # else:
            self.log.debug(
                "Opened NFC reader " + self.LIBNFC_READER
            )
            self.log.debug("Initing NFC reader")
        self.libnfc.nfc_initiator_init(self.device)
        if rfidiotglobals.Debug:
            self.log.debug("Configuring NFC reader")

        # Drop the field for a while
        self.libnfc.nfc_device_set_property_bool(self.device, NP_ACTIVATE_FIELD, False)

        # Let the reader only try once to find a tag
        self.libnfc.nfc_device_set_property_bool(self.device, NP_INFINITE_SELECT, False)
        self.libnfc.nfc_device_set_property_bool(self.device, NP_HANDLE_CRC, True)
        self.libnfc.nfc_device_set_property_bool(self.device, NP_HANDLE_PARITY, True)
        self.libnfc.nfc_device_set_property_bool(
            self.device, NP_ACCEPT_INVALID_FRAMES, True
        )
        # Enable field so more power consuming cards can power themselves up
        self.libnfc.nfc_device_set_property_bool(self.device, NP_ACTIVATE_FIELD, True)

    def deconfigure(self):
        if not self.device is None:
            if rfidiotglobals.Debug:
                self.log.debug("Deconfiguring NFC reader")
            # self.powerOff()
            self.libnfc.nfc_close(self.device)
            self.libnfc.nfc_exit(self.context)
            if rfidiotglobals.Debug:
                self.log.debug("Disconnected NFC reader")
            self.device = None
            self.context = ctypes.POINTER(ctypes.c_int)()

    def powerOn(self):
        self.libnfc.nfc_device_set_property_bool(self.device, NP_ACTIVATE_FIELD, True)
        if rfidiotglobals.Debug:
            self.log.debug("Powered up field")
        self.poweredUp = True

    def powerOff(self):
        self.libnfc.nfc_device_set_property_bool(self.device, NP_ACTIVATE_FIELD, False)
        if rfidiotglobals.Debug:
            self.log.debug("Powered down field")
        self.poweredUp = False

    def selectISO14443A(self):
        """Detect and initialise an ISO14443A card, returns an ISO14443A() object."""
        if rfidiotglobals.Debug:
            self.log.debug("Polling for ISO14443A cards")
        self.powerOff()
        self.powerOn()
        nm = NFC_MODULATION()
        nm.nmt = NMT_ISO14443A
        nm.nbr = NBR_106
        if self.libnfc.nfc_initiator_list_passive_targets(
            self.device, nm, ctypes.byref(self.tag), MAX_TARGET_COUNT
        ):
            return ISO14443A(self.tag[0].nti.nai)
        return None

    def selectISO14443B(self):
        """Detect and initialise an ISO14443B card, returns an ISO14443B() object."""
        if rfidiotglobals.Debug:
            self.log.debug("Polling for ISO14443B cards")
        self.powerOff()
        self.powerOn()
        nm = NFC_MODULATION()
        nm.nmt = NMT_ISO14443B
        nm.nbr = NBR_106
        if self.libnfc.nfc_initiator_list_passive_targets(
            self.device, nm, ctypes.byref(self.tag), MAX_TARGET_COUNT
        ):
            return ISO14443B(self.tag[0].nti.nbi)
        return None

    def selectJEWEL(self):
        """Detect and initialise a JEWEL card, returns a JEWEL() object."""
        if rfidiotglobals.Debug:
            self.log.debug("Polling for JEWEL cards")
        self.powerOff()
        self.powerOn()
        nm = NFC_MODULATION()
        target = (NFC_TARGET * MAX_TARGET_COUNT)()
        nm.nmt = NMT_JEWEL
        nm.nbr = NBR_106
        if self.libnfc.nfc_initiator_list_passive_targets(
            self.device, nm, ctypes.byref(target), MAX_TARGET_COUNT
        ):
            return JEWEL(target[0].nti.nji)
        return None

    def selectICLASS(self):
        """Detect and initialise an iClass card, returns an ICLASS() object."""
        if rfidiotglobals.Debug:
            self.log.debug("Polling for ICLASS cards")
        self.powerOff()
        self.powerOn()
        nm = NFC_MODULATION()
        target = (NFC_TARGET * MAX_TARGET_COUNT)()
        nm.nmt = NMT_ISO14443BICLASS
        nm.nbr = NBR_106
        if self.libnfc.nfc_initiator_list_passive_targets(
            self.device, nm, ctypes.byref(target), MAX_TARGET_COUNT
        ):
            return ICLASS(target[0].nti.nic)
        return None

    # ----------------------------------------------------- software ISO 14443-4
    def enable_software_tcl(self):
        """Take over ISO 14443-4 (T=CL) block handling from the reader firmware.

        Turns off libnfc "easy framing" so nfc_initiator_transceive_bytes carries
        raw frames; sendAPDU then wraps each APDU in the T=CL block protocol here
        (PCB block-number toggling, R(ACK) for receive-side chaining, S(WTX)
        echoes). Call it once, immediately after activation/RATS, while the card's
        block number is still 0. Used to work around the ACR122U chaining-buffer
        overflow (see configure()).
        """
        self.libnfc.nfc_device_set_property_bool(self.device, NP_EASY_FRAMING, False)
        # libnfc's default raw-transceive (InCommunicateThru) RF timeout is ~52 ms.
        # With easy framing on, libnfc extends it itself for ISO 14443-4 / WTX; with
        # it off we own T=CL, so a card's S(WTX) waiting-time-extension request (e.g.
        # ePassport BAC crypto, which needs longer than one frame time) would RF-error
        # at ~52 ms. Give raw frames a generous timeout so slow responses complete.
        # (A larger ceiling never slows fast responses - they return immediately.)
        self.libnfc.nfc_device_set_property_int(self.device, NP_TIMEOUT_COM, 3000)
        self._iblock = 0
        self.software_tcl = True
        if rfidiotglobals.Debug:
            self.log.debug("software T=CL enabled (easy framing off, COM timeout 3000ms)")

    def disable_software_tcl(self):
        "restore reader-firmware ISO 14443-4 framing"
        if self.software_tcl:
            self.libnfc.nfc_device_set_property_bool(self.device, NP_EASY_FRAMING, True)
        self.software_tcl = False

    # set Mifare specific parameters
    def configMifare(self):
        # raw Mifare Classic framing - never the software T=CL path
        self.software_tcl = False
        self.libnfc.nfc_device_set_property_bool(self.device, NP_AUTO_ISO14443_4, False)
        self.libnfc.nfc_device_set_property_bool(self.device, NP_EASY_FRAMING, True)
        self.selectISO14443A()

    def _raw_frame(self, apdu, timeout=None):
        "transceive one frame (hex in -> (ok, hex) out); returns (False, rxlen) on error"
        txData = []
        for i in range(0, len(apdu), 2):
            txData.append(int(apdu[i : i + 2], 16))

        txAPDU = ctypes.c_ubyte * len(txData)
        tx = txAPDU(*txData)

        rxAPDU = ctypes.c_ubyte * MAX_FRAME_LEN
        rx = rxAPDU()

        if rfidiotglobals.Debug:
            self.log.debug(
                "Sending %d byte APDU: %s"
                % (len(tx), "".join([f"{x:02x}" for x in tx]))
            )
        rxlen = self.libnfc.nfc_initiator_transceive_bytes(
            self.device,
            ctypes.byref(tx),
            ctypes.c_size_t(len(tx)),
            ctypes.byref(rx),
            ctypes.c_size_t(len(rx)),
            int(timeout * 1000) if timeout is not None else -1,
        )
        if rfidiotglobals.Debug:
            self.log.debug("APDU rxlen = " + str(rxlen))
        if rxlen < 0:
            self.libnfc.nfc_perror(self.device, "nfc_initiator_transceive_bytes")
            if rfidiotglobals.Debug:
                self.log.error("Error sending/receiving APDU")
            return False, rxlen
        # else:
        rxAPDU = "".join([f"{x:02x}" for x in rx[:rxlen]])
        if rfidiotglobals.Debug:
            self.log.debug(f"Received {rxlen} byte APDU: {rxAPDU}")
        return True, rxAPDU.upper()

    def _plain_apdu(self, apdu, timeout=None):
        "non-T=CL path: a straight libnfc transceive (reader-firmware framing)"
        return self._raw_frame(apdu, timeout)


# --------------------------------------------------------------------------- #
# Direct-CCID ACR122U backend                                                 #
#                                                                             #
# Some ACR122U units (e.g. the ACR122U-WB-R, which enumerates with the ACR38  #
# PID 072f:90cc) are misidentified by every off-the-shelf driver: libnfc's    #
# acr122_usb init fails to bring them up, and libccid loads its ACR38 *contact*#
# driver and mis-negotiates the contactless card as T=0. The PN532 itself is  #
# fine, though - it answers raw CCID perfectly. This backend talks straight to #
# the reader's CCID bulk endpoints over usbdevfs (no libnfc, no pcscd), wraps  #
# PN532 commands in ACR122U pseudo-APDUs, and drives ISO 14443-4 with the same #
# software T=CL engine (_tcl_exchange) as the libnfc path, so long chained     #
# responses never hit the PN532's reassembly-buffer overflow.                 #
#                                                                             #
# Select it with  -f ccid  (first ACS reader) or  -f ccid:<bus>:<dev>.        #
# --------------------------------------------------------------------------- #

import os as _os
import glob as _glob

# usbdevfs ioctls (asm-generic _IOC encoding)
def _IOC(d, t, nr, sz):
    return (d << 30) | (sz << 16) | (t << 8) | nr
_USBDEVFS_CLAIMINTERFACE = _IOC(2, 0x55, 15, 4)
_USBDEVFS_RELEASEINTERFACE = _IOC(2, 0x55, 16, 4)
_USBDEVFS_BULK = _IOC(3, 0x55, 2, 24)   # sizeof(struct usbdevfs_bulktransfer) on LP64


class _usbdevfs_bulktransfer(ctypes.Structure):
    _fields_ = [
        ("ep", ctypes.c_uint),
        ("len", ctypes.c_uint),
        ("timeout", ctypes.c_uint),   # ms
        ("data", ctypes.c_void_p),
    ]


class ACR122CCID(_ISODEP):
    """Drive an ACR122U directly over its CCID bulk endpoints (no libnfc/pcscd).

    Presents the same surface RFIDIOt uses on the libnfc path (selectISO14443A,
    sendAPDU, enable_software_tcl, powerOn/powerOff, is_acr122, LIBNFC_READER),
    so it is a drop-in for pynfc.NFC when the connstring starts with "ccid".
    """

    # ACR122U CCID bulk endpoints (standard for this reader)
    EP_OUT = 0x02
    EP_IN = 0x82

    def __init__(self, spec, listonly=False):
        self.spec = spec
        self.software_tcl = False
        self._iblock = 0
        self.is_acr122 = True
        self.LIBNFC_CONNSTRING = spec
        self.LIBNFC_VER = "direct-ccid"
        self.poweredUp = False
        self._seq = 0
        self._libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        self.log = logging.getLogger("pynfc.ccid")
        if not self.log.handlers:
            sh = logging.StreamHandler()
            sh.setFormatter(logging.Formatter("%(asctime)s: %(levelname)s - %(message)s"))
            self.log.addHandler(sh)
        self.log.setLevel(logging.DEBUG)

        node, bus, dev = self._find(spec)
        self.LIBNFC_READER = "ACS ACR122U (direct CCID, bus %d dev %d)" % (bus, dev)
        self._fd = _os.open(node, _os.O_RDWR)
        self._claimed = False
        try:
            self._ioctl(_USBDEVFS_CLAIMINTERFACE, ctypes.byref(ctypes.c_uint(0)))
            self._claimed = True
        except OSError as e:
            _os.close(self._fd)
            raise ConnectionAbortedError(
                "cannot claim ACR122U interface (%s) - is pcscd holding it? "
                "stop it with: sudo systemctl stop pcscd pcscd.socket" % e
            )
        if not listonly:
            self._pn532_init()

    # -- device discovery ---------------------------------------------------
    @staticmethod
    def _find(spec):
        "resolve a 'ccid[:bus:dev]' spec to (node, bus, dev) via sysfs"
        want_bus = want_dev = None
        parts = spec.split(":")
        if len(parts) >= 3:
            want_bus, want_dev = int(parts[1]), int(parts[2])
        for d in sorted(_glob.glob("/sys/bus/usb/devices/*")):
            try:
                with open(d + "/idVendor") as f:
                    vid = int(f.read().strip(), 16)
                with open(d + "/busnum") as f:
                    bus = int(f.read().strip())
                with open(d + "/devnum") as f:
                    dev = int(f.read().strip())
            except (OSError, ValueError):
                continue
            if want_bus is not None:
                if bus != want_bus or dev != want_dev:
                    continue
            elif vid != 0x072F:          # ACS (Advanced Card Systems)
                continue
            return "/dev/bus/usb/%03d/%03d" % (bus, dev), bus, dev
        raise ConnectionAbortedError("no ACS/ACR122U USB device found for '%s'" % spec)

    # -- low-level CCID transport ------------------------------------------
    def _ioctl(self, req, arg):
        r = self._libc.ioctl(self._fd, ctypes.c_ulong(req), arg)
        if r < 0:
            e = ctypes.get_errno()
            raise OSError(e, _os.strerror(e))
        return r

    def _bulk(self, ep, data, timeout_ms):
        if data is not None:
            buf = (ctypes.c_ubyte * len(data))(*data)
            bt = _usbdevfs_bulktransfer(ep, len(data), timeout_ms,
                                        ctypes.cast(buf, ctypes.c_void_p))
            return self._ioctl(_USBDEVFS_BULK, ctypes.byref(bt))
        buf = (ctypes.c_ubyte * 512)()
        bt = _usbdevfs_bulktransfer(ep, 512, timeout_ms,
                                    ctypes.cast(buf, ctypes.c_void_p))
        n = self._ioctl(_USBDEVFS_BULK, ctypes.byref(bt))
        return bytes(buf[:n])

    def _xfrblock(self, apdu, timeout_ms):
        "one CCID PC_to_RDR_XfrBlock -> the reader's response data (after header)"
        self._seq = (self._seq + 1) & 0xFF
        n = len(apdu)
        hdr = [0x6F, n & 0xFF, (n >> 8) & 0xFF, (n >> 16) & 0xFF, (n >> 24) & 0xFF,
               0x00, self._seq, 0x00, 0x00, 0x00]
        self._bulk(self.EP_OUT, hdr + list(apdu), timeout_ms)
        while True:
            r = self._bulk(self.EP_IN, None, timeout_ms)
            if len(r) < 10:
                return b""
            # bStatus bmCommandStatus == 10b: "time extension", card still working
            if (r[7] & 0xC0) == 0x80:
                continue
            dlen = r[1] | (r[2] << 8) | (r[3] << 16) | (r[4] << 24)
            return bytes(r[10:10 + dlen])

    def _apdu(self, apdu, timeout_ms):
        "send a reader APDU, following T=0 61xx GET RESPONSE chaining"
        out = bytearray()
        resp = self._xfrblock(apdu, timeout_ms)
        while len(resp) >= 2 and resp[-2] == 0x61:
            out += resp[:-2]
            # GET RESPONSE uses the ACR122U pseudo-APDU class FF, not T=0's 00
            resp = self._xfrblock([0xFF, 0xC0, 0x00, 0x00, resp[-1]], timeout_ms)
        out += resp
        return bytes(out)

    def _pn532(self, cmd, timeout_ms=3000):
        "wrap a PN532 command (starting 0xD4) in the ACR122U direct-transmit pseudo-APDU"
        apdu = [0xFF, 0x00, 0x00, 0x00, len(cmd)] + list(cmd)
        r = self._apdu(apdu, timeout_ms)
        if len(r) >= 2 and r[-2] == 0x90 and r[-1] == 0x00:
            r = r[:-2]
        return r   # expect D5 <cmd+1> ...

    def _read_reg(self, addr):
        r = self._pn532([0xD4, 0x06, (addr >> 8) & 0xFF, addr & 0xFF])
        return r[2] if len(r) >= 3 else 0

    def _write_reg(self, addr, val):
        self._pn532([0xD4, 0x08, (addr >> 8) & 0xFF, addr & 0xFF, val & 0xFF])

    # -- PN532 setup --------------------------------------------------------
    def _pn532_init(self):
        self._pn532([0xD4, 0x14, 0x01, 0x00])             # SAMConfiguration: normal mode
        # limit passive-activation retries so selectISO14443A() returns promptly
        # when no card is present (mirrors libnfc NP_INFINITE_SELECT = false)
        self._pn532([0xD4, 0x32, 0x05, 0xFF, 0x01, 0x02])  # RFConfiguration: MaxRetries
        self.poweredUp = True

    def _timeout_ms(self, timeout):
        # T=CL callers pass a per-op timeout in seconds; give slow responses
        # (e.g. ePassport BAC crypto / S(WTX)) plenty of room, never less than 3 s
        if timeout is None:
            return 5000
        return max(int(timeout * 1000), 3000)

    # -- API expected by RFIDIOt -------------------------------------------
    def powerOn(self):
        self._pn532([0xD4, 0x32, 0x01, 0x01])   # RFConfiguration: RF field on
        self.poweredUp = True

    def powerOff(self):
        self._pn532([0xD4, 0x32, 0x01, 0x00])   # RFConfiguration: RF field off
        self.poweredUp = False

    def selectISO14443A(self):
        """Poll for a 106 kbps ISO 14443-A target, return an ISO14443A() object."""
        r = self._pn532([0xD4, 0x4A, 0x01, 0x00])   # InListPassiveTarget, 1 target, 106A
        # D5 4B <NbTg> [Tg SENS_RES(2) SEL_RES(1) IDlen ID... [ATS...]]
        if len(r) < 4 or r[0] != 0xD5 or r[1] != 0x4B or r[2] == 0:
            return None
        p = 4                       # skip D5 4B NbTg Tg
        sens = r[p:p + 2]; p += 2
        sel = r[p]; p += 1
        idlen = r[p]; p += 1
        uid = r[p:p + idlen]; p += idlen
        ats = r[p:]                 # remaining bytes are the ATS (if any)
        return _SimpleTargetA(uid, ats, sens, sel)

    def selectISO14443B(self):
        return None                 # not implemented for the direct-CCID path

    def selectJEWEL(self):
        return None

    def selectICLASS(self):
        return None

    def enable_software_tcl(self):
        """Take over ISO 14443-4 (T=CL) handling (see configure()/libnfc path).

        Each raw I-block goes out via PN532 InCommunicateThru, so the reader's
        firmware never reassembles a chained response and cannot overflow. CRC is
        left to the PN532 (CIU TxCRCEn/RxCRCEn), matching libnfc's HANDLE_CRC.
        """
        self._set_crc(True)
        # Extend the PN532 InCommunicateThru RF timeout (RFConfiguration item 0x02
        # fRetryTimeout; Timeout = 100us * 2^(n-1), so 0x10 ~= 3.3 s) so a card's
        # S(WTX) waiting-time extension - e.g. ePassport BAC EXTERNAL AUTHENTICATE
        # running 3DES on-chip - doesn't hit the ~52 ms default and RF-error. This
        # is the direct-CCID analogue of raising libnfc's NP_TIMEOUT_COM.
        self._pn532([0xD4, 0x32, 0x02, 0x00, 0x0B, 0x10])
        self._iblock = 0
        self.software_tcl = True
        if rfidiotglobals.Debug:
            self.log.debug("software T=CL enabled (direct CCID, InCommunicateThru)")

    def disable_software_tcl(self):
        self.software_tcl = False

    def configMifare(self):
        self.software_tcl = False
        self.selectISO14443A()

    def _set_crc(self, on):
        "set/clear the PN532 CIU automatic-CRC bits for InCommunicateThru"
        for reg in (0x6302, 0x6303):        # CIU_TxMode, CIU_RxMode; bit7 = CRCEn
            v = self._read_reg(reg)
            v = (v | 0x80) if on else (v & ~0x80)
            self._write_reg(reg, v)

    def _raw_frame(self, apdu, timeout=None):
        "transceive one ISO 14443-4 frame via PN532 InCommunicateThru"
        frame = [int(apdu[i:i + 2], 16) for i in range(0, len(apdu), 2)]
        if rfidiotglobals.Debug:
            self.log.debug("CCID TX frame: %s" % apdu)
        r = self._pn532([0xD4, 0x42] + frame, self._timeout_ms(timeout))   # InCommunicateThru
        # D5 43 <status> <card bytes, CRC already stripped by the PN532>
        if len(r) < 3 or r[0] != 0xD5 or r[1] != 0x43:
            return False, -1
        if r[2] != 0x00:                     # PN532 error status (ETIMEOUT, ERFPROTO, ...)
            if rfidiotglobals.Debug:
                self.log.error("InCommunicateThru status 0x%02X" % r[2])
            return False, -1
        resp = "".join("%02X" % b for b in r[3:])
        if rfidiotglobals.Debug:
            self.log.debug("CCID RX frame: %s" % resp)
        return True, resp

    def _plain_apdu(self, apdu, timeout=None):
        "non-T=CL path: PN532 InDataExchange (firmware framing; MIFARE, short APDUs)"
        frame = [int(apdu[i:i + 2], 16) for i in range(0, len(apdu), 2)]
        r = self._pn532([0xD4, 0x40, 0x01] + frame, self._timeout_ms(timeout))   # InDataExchange, Tg 1
        if len(r) < 3 or r[0] != 0xD5 or r[1] != 0x41 or r[2] != 0x00:
            return False, -1
        return True, "".join("%02X" % b for b in r[3:])

    def listreaders(self, target=None):
        print("Direct-CCID reader:", self.LIBNFC_READER)
        return None

    def deconfigure(self):
        fd = getattr(self, "_fd", None)
        if fd is not None:
            try:
                if getattr(self, "_claimed", False):
                    self._ioctl(_USBDEVFS_RELEASEINTERFACE, ctypes.byref(ctypes.c_uint(0)))
            except OSError:
                pass
            try:
                _os.close(fd)
            except OSError:
                pass
            self._fd = None

    def __del__(self):
        self.deconfigure()


class _SimpleTargetA():
    "ISO14443A-compatible view of a PN532 InListPassiveTarget result"
    def __init__(self, uid, ats, sens, sel):
        self.uid = "".join("%02X" % b for b in uid)
        self.atr = "".join("%02X" % b for b in ats)
        self.atqa = "".join("%02X" % b for b in sens)
        self.sak = "%02X" % sel

    def __str__(self):
        return "ISO14443A(uid='%s', atr='%s', atqa='%s', sak='%s')" % (
            self.uid, self.atr, self.atqa, self.sak)


def target_is_present(self):
    ret = self.libnfc.nfc_initiator_target_is_present(self.device, self.tag[0])
    return ret == 0, ret


if __name__ == "__main__":
    n = NFC()
    n.powerOn()
    c = n.readISO14443A()
    print("UID: " + c.uid)
    print("ATR: " + c.atr)
    print("ATQA: " + c.atqa)
    print("SAK: " + c.sak)

    cont = True
    while cont:
        apdu = input("enter the apdu to send now:")
        if apdu == "exit":
            cont = False
        else:
            r = n.sendAPDU(apdu)
            print(r)

    print("Ending now ...")
    n.deconfigure()
