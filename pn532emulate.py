#!/usr/bin/python3
#  pn532emulate.py - switch NXP PN532 reader chip into TAG emulation mode
#
#  Adam Laurie <adam@algroup.co.uk>
#  http://rfidiot.org/
#
#  This code is copyright (c) Adam Laurie, 2009, All rights reserved.
#  For non-commercial use only, the following terms apply - for all other
#  uses, please contact the author:
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


import sys
# import os

try:
    import rfidiot
    from rfidiot.pn532 import *
    card = rfidiot.card
except Exception as e:
    print("Couldn't open reader! (%s)" % e)
    sys.exit(True)

args = rfidiot.args
chelp = rfidiot.help

card.info("pn532emulate v3.0f")

if chelp or len(args) < 6:
    print(sys.argv[0] + " - Switch NXP PN532 chip into emulation mode")
    print()
    print(
        "Usage: "
        + sys.argv[0]
        + " <MODE> <SENS_RES> <NFCID1t> <SEL_RES> <NFCID2t> <PAD> <SYSTEM_CODE> <NFCID3t> [General Bytes] [Historical Bytes]"
    )
    print()
    print("  The NXP PN532 chip inside some readers (such as ACS/Tikitag) are capable of emulating the following tags:")
    print()
    print("    ISO-14443-3")
    print("    ISO-14443-4")
    print("    Mifare")
    print("    FeliCa")
    print()
    print("  Arguments should be specified as follows:")
    print()
    print("    MODE (BitField, last 3 bits only):")
    print("        -----000 - Any")
    print("        -----001 - Passive only")
    print("        -----010 - DEP only")
    print("        -----100 - PICC only")
    print()
    print("    SENS_RES:")
    print("        2 Bytes, LSB first, as defined in ISO 14443-3.")
    print()
    print("    NFCID1t:")
    print("        UID Last 6 HEX digits (3 bytes). The PN532 target mode takes only a")
    print("        3-byte NFCID1t and always transmits a single-size (4-byte) UID whose")
    print("        first byte is hard-wired to '08' (the ISO 14443-3 cascade-tag /")
    print("        random-UID marker), so '08' is prepended and byte 0 cannot be set to")
    print("        anything else here. For a UID of your choice (4, 7 or 10 bytes) at the")
    print("        ISO 14443-3 layer, use emulateuid.py (libnfc PN53x), or a Proxmark3 /")
    print("        Chameleon. '08' is exact for ICAO 9303 ePassports, whose UIDs are")
    print("        random and already start with '08'.")
    print()
    print("    SEL_RES:")
    print("        1 Byte, as defined in ISO14443-4.")
    print()
    print("    NFCID2t:")
    print("        8 Bytes target NFC ID2. Must start with '01fe'.")
    print()
    print("    PAD:")
    print("        8 Bytes.")
    print()
    print("    SYSTEM_CODE:")
    print("        2 Bytes, returned in the POL_RES frame if the 4th byte of the incoming POL_REQ")
    print("        command frame is 0x01.")
    print()
    print("    NFCID3t:")
    print("        10 Bytes, used in the ATR_RES in case of ATR_REQ received from the initiator.")
    print()
    print("    General Bytes:")
    print("        Optional, Max 47 Bytes, to be used in the ATR_RES.")
    print()
    print("    Historical Bytes:")
    print("        Optional, Max 48 Bytes, to be used in the ATS when in ISO/IEC 14443-4 PICC")
    print("        emulation mode.")
    print()
    print("  Example:")
    print()
    print(
        "    " + sys.argv[0] + " 00 0800 dc4420 60 01fea2a3a4a5a6a7c0c1c2c3c4c5c6c7ffff aa998877665544332211 00 52464944494f7420504e353332"
    )
    print()
    print("    In ISO/IEC 14443-4 PICC emulation mode, the emulator will wait for initiator, then wait for an APDU,")
    print("    to which it will reply '9000' and exit.")
    print()
    print("    With a libnfc reader (-f) the SEL_RES (SAK) selects the emulated tag class:")
    print("      SAK with bit 0x20 (e.g. 20) -> ISO 14443-4 (Type 4): reader sends RATS,")
    print("        we answer with the ATS (Historical Bytes) then reply 9000 to each APDU.")
    print("      SAK without bit 0x20 (e.g. 00) -> ISO 14443-3 (Type 2): we serve READ")
    print("        commands from a small memory image (Mifare Ultralight-style).")
    print("      (A PN533 reader, e.g. the SCL3711, can't run T=CL in hardware for Type 4")
    print("       here - use an ACR122U/PN532; or relayuid.py, which runs T=CL on the host")
    print("       and so does full Type 4 emulation on a PN533 too.)")
    print()
    sys.exit(True)

if card.readertype != card.READER_LIBNFC and card.readersubtype != card.READER_ACS:
    print("  Reader type not supported!")
    sys.exit(True)

# switch off auto-polling (for ACS v1 firmware only) (doesn't seem to help anyway!)
# if not card.acs_send_apdu(card.PCSC_APDU['ACS_DISABLE_AUTO_POLL']):
#       print '  Could not disable auto-polling'
#       sys.exit(True)

if card.readersubtype == card.READER_ACS:
    if card.acs_send_apdu(PN532_APDU["GET_PN532_FIRMWARE"]):
        print("  NXP PN532 Firmware:")
        pn532_print_firmware(card.data)

    if card.acs_send_apdu(PN532_APDU["GET_GENERAL_STATUS"]):
        pn532_print_status(card.data)

mode = [args[0]]
sens_res = [args[1]]
# NFCID1t is only 3 bytes; in target mode the PN532 always emits a single-size
# UID with byte 0 hard-wired to 0x08, so only these low 3 bytes are settable and
# '08' is prepended on the wire (see the usage text above).
uid = [args[2]]
sel_res = [args[3]]
felica = [args[4]]
nfcid = [args[5]]
try:
    lengt = ["%02x" % (len(args[6]) // 2)]
    gt = [args[6]]
except:
    lengt = ["00"]
    gt = [""]
try:
    lentk = ["%02x" % (len(args[7]) // 2)]
    tk = [args[7]]
except:
    lentk = ["00"]
    tk = [""]

def _emulate_tcl_libnfc(card, first):
    """Type 4 (ISO 14443-4) target loop.

    Easy framing is left ON (see the initAsTarget call), so the reader chip
    drives the ISO 14443-4 (T=CL) block protocol - RATS/ATS, PCB block numbers,
    CID, chaining, WTX - and we exchange bare APDUs. We just reply 9000 to each
    command (a stub; a real emulator would dispatch on the APDU). This is how
    libnfc's own nfc-emulate-forum-tag4 works and runs on ACR122U/PN532.

    `first` is whatever nfc_target_init returned: normally empty (the chip has
    just answered the RATS) or already the first APDU. If it is a RATS ('E0 ..')
    the chip did NOT handle T=CL itself in this easy-framing mode - the PN533/
    SCL3711 case (target receive returns NFC_ENOTIMPL). Report it rather than
    limp along; relayuid.py does Type 4 on a PN533 by running T=CL on the host.
    """
    if first[:2] == "E0":
        print("Reader handed up the RATS (%s) instead of answering it in "
              "hardware: this chip won't run T=CL itself in easy-framing target "
              "mode (the PN533/SCL3711 case). Use an ACR122U/PN532 here, or "
              "relayuid.py, which runs T=CL on the host and emulates Type 4 on a "
              "PN533 too." % first)
        sys.exit(True)
    status, data = (True, first) if first else card.nfc.targetReceive(0)

    guard = 0
    while status:
        guard += 1
        if guard > 4096:
            print("ISO 14443-4 exchange did not terminate")
            sys.exit(True)
        print("<<", data)
        print(">>", card.ISO_OK)
        status, ret = card.nfc.targetSend(card.ISO_OK, 0)
        if not status:
            print("response send failed (libnfc rc %s)" % ret)
            sys.exit(True)
        status, data = card.nfc.targetReceive(0)

    # receive returned an error (initiator left the field, or ENOTIMPL)
    if data == -8:
        print("Target receive not supported (libnfc NFC_ENOTIMPL): this reader "
              "won't run T=CL in easy-framing target mode. Use an ACR122U/PN532, "
              "or relayuid.py (host-side T=CL, works on a PN533).")
    else:
        print("Target receive ended (libnfc rc %s)" % data)
    sys.exit(False)


def _emulate_type2_libnfc(card, uid_full, first):
    """Type 2 (ISO 14443-3 / NFC Forum Type 2) target loop (libnfc raw framing).

    The reader issues raw commands (no RATS). Answer READ (0x30 <page>) with 16
    bytes - four pages, wrapping - from a small static memory image, and
    acknowledge HALT (0x50). Writes (0xA2) and other commands are not
    implemented: a 4-bit NAK cannot be sent through the byte-oriented API, so
    they are logged and the exchange waits for the next command. `first` is the
    command captured during activation ('' if none).
    """
    # 16 pages x 4 bytes. page 0 holds the first 4 UID bytes; page 3 is the NFC
    # Forum capability container (E1 10 06 00 = magic, v1.0, 48 bytes, R/W);
    # page 4 is an empty NDEF TLV. Enough to read as a blank Type 2 tag.
    pages = ["00000000"] * 16
    pages[0] = (uid_full + "0" * 8)[:8]
    pages[3] = "E1100600"
    pages[4] = "0300FE00"

    def read16(page):
        return "".join(pages[(page + i) % len(pages)] for i in range(4))

    print("  ISO 14443-3 (Type 2) target - serving %d pages" % len(pages))
    status, data = True, first
    if not data:
        status, data = card.nfc.targetReceive(0)

    guard = 0
    while status:
        guard += 1
        if guard > 100000:
            print("Type 2 exchange did not terminate")
            sys.exit(True)
        if len(data) < 2:
            status, data = card.nfc.targetReceive(0)
            continue
        cmd = int(data[0:2], 16)
        if cmd == 0x30:  # READ <page>
            page = int(data[2:4], 16) if len(data) >= 4 else 0
            resp = read16(page)
            print("<< READ %02X" % page)
            print(">>", resp)
            ok, ret = card.nfc.targetSend(resp, 0)
            if not ok:
                print("response send failed (libnfc rc %s)" % ret)
                sys.exit(True)
        elif cmd == 0x50:  # HALT
            print("<< HALT")
            print("  Initiator halted")
            sys.exit(False)
        else:
            print("<< unsupported Type 2 command:", data)
        status, data = card.nfc.targetReceive(0)

    print("Target receive ended (libnfc rc %s)" % data)
    sys.exit(False)


if card.readertype == card.READER_LIBNFC:
    # libnfc card-emulation path. libnfc's target API only expresses an
    # ISO 14443-A PICC, so the PN532-specific MODE byte, the FeliCa parameters
    # (NFCID2t/PAD/SYSTEM_CODE), NFCID3t and the DEP General Bytes that the
    # ACR122U path accepts have no equivalent here and are ignored. SENS_RES
    # becomes the ATQA, '08'+NFCID1t the (single-size) UID, SEL_RES the SAK and
    # the Historical Bytes the ATS.
    for ignored, label in (
        (mode[0], "MODE"),
        (felica[0], "NFCID2t/FeliCa params"),
        (nfcid[0], "NFCID3t"),
        (gt[0], "General Bytes (DEP)"),
    ):
        if ignored:
            print("  Note: %s ignored (libnfc ISO 14443-A target only)" % label)
    uid_full = "08" + uid[0]
    # Tag class comes from the SAK (SEL_RES) we present: bit 0x20 advertises
    # ISO 14443-4 -> Type 4 (reader does RATS/T=CL/APDUs), otherwise Type 2 (raw
    # ISO 14443-3 reads). This drives the framing we ask libnfc for:
    #   Type 4 -> easy framing ON, so the reader chip runs T=CL and we trade
    #             bare APDUs (works on ACR122U/PN532);
    #   Type 2 -> raw framing, so we serve the ISO 14443-3 commands ourselves.
    is_type4 = bool(int(sel_res[0], 16) & 0x20)
    target = card.nfc.make_iso14443a_target(sens_res[0], uid_full, sel_res[0], tk[0])
    print("  Waiting for activation...")
    status, data = card.nfc.initAsTarget(target, 0, raw=not is_type4)
    if not status:
        print("Target Init failed (libnfc rc %s)" % data)
        sys.exit(True)
    print("  Emulator activated:")
    print("         UID: %s" % uid_full)
    if data:
        print("    First RX:", data)
    print()

    if is_type4:
        _emulate_tcl_libnfc(card, data)
    else:
        _emulate_type2_libnfc(card, uid_full, data)
    sys.exit(False)

print("  Waiting for activation...")
card.acs_send_apdu(card.PCSC_APDU["ACS_LED_RED"])
status = card.acs_send_apdu(PN532_APDU["TG_INIT_AS_TARGET"] + mode + sens_res + uid + sel_res + felica + nfcid + lengt + gt + lentk + tk)
if not status or card.data[:4] != "D58D":
    print("Target Init failed:", card.errorcode)
    sys.exit(True)
mode = int(card.data[4:6], 16)
baudrate = mode & 0x70
print("  Emulator activated:")
print("         UID: 08%s" % uid[0])
print("    Baudrate:", PN532_BAUDRATES[baudrate])
print("        Mode:", end="")
if mode & 0x08:
    print("ISO/IEC 14443-4 PICC")
if mode & 0x04:
    print("DEP")
framing = mode & 0x03
print("     Framing:", PN532_FRAMING[framing])
print("   Initiator:", card.data[6:])
print()

print("  Waiting for APDU...")
status = card.acs_send_apdu(PN532_APDU["TG_GET_DATA"])
if not status or card.data[:4] != "D587":
    print("Target Get Data failed:", card.errorcode)
    print("Data:", card.data)
    sys.exit(True)
errorcode = int(card.data[4:6], 16)
if errorcode:  # != 0
    print("Error:", PN532_ERRORS[errorcode])
    sys.exit(True)
print("<<", card.data[6:])

print(">>", card.ISO_OK)
status = card.acs_send_apdu(PN532_APDU["TG_SET_DATA"] + [card.ISO_OK])
if not status:
    sys.exit(True)
else:
    sys.exit(False)
