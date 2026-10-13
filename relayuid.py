#!/usr/bin/python3
#  relayuid.py - [EXPERIMENTAL / WORK IN PROGRESS] full ISO 14443-4 emulation on a
#  libnfc PN53x with a UID of your choice: answer anticollision with any UID
#  (as emulateuid.py does), then run the ISO 14443-4 (T=CL) block protocol on the
#  target side - answer the RATS with an ATS and handle I-blocks - so a reader
#  both sees our UID AND can exchange APDUs. The APDUs are answered by a responder:
#  a stub (reply 9000 / a GET CHALLENGE) by default, or relayed to a real card on
#  a second reader with -c (the "full relay": real UID + real card behaviour).
#
#  This is the thing a naive merge of emulateuid + pn532mitm would imply, but it
#  is a distinct mode (host owns anticollision AND T=CL) - see TODO section 17a.
#
#  Adam Laurie <adam@algroup.co.uk>
#  http://rfidiot.org/
#
#    This code is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.

import getopt
import os
import sys
import time

import rfidiot

card = rfidiot.card
args = rfidiot.args

card.info("relayuid v0.1a (EXPERIMENTAL)")


def crc_a(data):
    "ISO 14443-3 CRC_A of bytes, as 2 bytes LSB first"
    crc = 0x6363
    for b in data:
        b ^= crc & 0xFF
        b = (b ^ (b << 4)) & 0xFF
        crc = (crc >> 8) ^ (b << 8) ^ (b << 3) ^ (b >> 4)
    return bytes([crc & 0xFF, crc >> 8])


def usage():
    print()
    print(sys.argv[0] + " - emulate a full ISO 14443-4 card with a chosen UID (experimental)")
    print()
    print("Usage: %s [options] <UID>" % sys.argv[0])
    print()
    print("  UID is 4, 7 or 10 bytes of HEX (a 4-byte UID may not start with 88)")
    print()
    print("  Options:")
    print("    -a <ATQA>     ATQA on the wire (default 0400/4400/8400 by UID size)")
    print("    -k <SAK>      final SAK (default 20 = ISO 14443-4; the reader then sends RATS)")
    print("    -c <READER>   relay APDUs to a real card on this reader (libnfc connstring,")
    print("                  or ccid[:bus:dev]); without -c a stub answers (9000 / GET CHALLENGE)")
    print("    -w <SECONDS>  stop after this many seconds (default: run until Ctrl-C)")
    print()
    print("  The emulator must be a libnfc PN53x (-f), e.g. an SCL3711. Priming works as")
    print("  in emulateuid.py: a reader that retries after the failed RATS, then our UID.")
    print()


if rfidiot.help:
    usage()
    sys.exit(False)

try:
    opts, args = getopt.getopt(args, "a:k:c:w:")
except getopt.GetoptError as e:
    print("  " + str(e))
    usage()
    sys.exit(True)

atqa = None
sak = 0x20
relay = None
wait = 0
try:
    for o, a in opts:
        if o == "-a":
            atqa = bytes.fromhex(a)
            assert len(atqa) == 2
        elif o == "-k":
            sak = int(a, 16)
        elif o == "-c":
            relay = a
        elif o == "-w":
            wait = float(a)
    uid = bytes.fromhex(args[0])
    assert len(uid) in (4, 7, 10)
except (ValueError, AssertionError, IndexError):
    usage()
    sys.exit(True)

if card.readertype != card.READER_LIBNFC or not hasattr(card.nfc, "initAsTarget"):
    print("  The emulator must be a libnfc PN53x reader (-f <connstring>)")
    sys.exit(True)

# --- cascade levels for the chosen UID (as emulateuid.py) -------------------
if atqa is None:
    atqa = {4: b"\x04\x00", 7: b"\x44\x00", 10: b"\x84\x00"}[len(uid)]
if len(uid) == 4:
    parts = [uid]
elif len(uid) == 7:
    parts = [b"\x88" + uid[0:3], uid[3:7]]
else:
    parts = [b"\x88" + uid[0:3], b"\x88" + uid[3:6], uid[6:10]]
levels = []
for n, part in enumerate(parts):
    bcc = part[0] ^ part[1] ^ part[2] ^ part[3]
    final = n == len(parts) - 1
    level_sak = (sak & ~0x04) if final else 0x04
    levels.append((0x93 + 2 * n, part + bytes([bcc]), bytes([level_sak]) + crc_a(bytes([level_sak]))))

# ATS we present after the RATS: TL=05, T0=78 (TA1/TB1/TC1 present, FSCI=8 -> 256),
# TA1=80 (106 kbps both ways), TB1=80 (FWI=8 ~77 ms, room for a relayed reply),
# TC1=00 (no CID, no NAD). No historical bytes.
ATS = bytes.fromhex("0578808000")

# --- APDU responder: stub, or relay to a real card --------------------------
relay_reader = None


def open_relay(spec):
    "open a second reader to relay APDUs to a real card; returns a send(apdu_hex)->resp_hex"
    if spec.lower().startswith("ccid"):
        from rfidiot.pynfc import ACR122CCID
        r = ACR122CCID(spec)
        r.selectISO14443A()
    else:
        from rfidiot.pynfc import NFC
        r = NFC(spec)
        r.selectISO14443A()
    def send(apdu_hex):
        ok, resp = r.sendAPDU(apdu_hex, 3)
        return resp if ok else None
    return r, send


def stub(apdu_hex):
    "minimal card: SELECT->9000, GET CHALLENGE->8 random bytes+9000, else 9000"
    a = bytes.fromhex(apdu_hex)
    if len(a) >= 2 and a[1] == 0x84:          # GET CHALLENGE
        return os.urandom(8).hex().upper() + "9000"
    return "9000"


if relay:
    try:
        relay_reader, responder = open_relay(relay)
        print("  Relaying APDUs to real card on %s" % relay)
    except Exception as e:
        print("  Could not open relay reader '%s': %s" % (relay, e))
        sys.exit(True)
else:
    responder = stub
    print("  Stub responder (no -c): replying 9000 / GET CHALLENGE")

# --- prime (as emulateuid.py): SAK 20 provokes a RATS that breaks AutoColl ---
prime_uid = "08" + os.urandom(3).hex().upper()
nt = card.nfc.make_iso14443a_target("0400", prime_uid, "20")

print()
print("  Emulating ISO 14443-4 card UID %s (ATQA %s, SAK %02X)" % (uid.hex().upper(), atqa.hex().upper(), sak))
print("  Waiting for the real reader to prime us (its first activation will fail)...")
ok, first = card.nfc.initAsTarget(nt, int(wait * 1000) if wait else 0)
if not ok:
    print("  Not activated (%s)" % first)
    sys.exit(True)
print("  %.3f primed (by %s); now present the UID to a reader (Ctrl-C to stop)" % (time.time(), prime_uid))
print()

# host now owns every layer: anticollision frames carry no CRC, and we append
# CRC_A to the ATS / I-blocks by hand
card.nfc.targetHandleCRC(False)
start = time.time()
halted = False
level = 0
activated = False
shown = {}


def send(tx_bytes, crc=False):
    data = tx_bytes + (crc_a(tx_bytes) if crc else b"")
    card.nfc.targetSend(data.hex())


try:
    while not wait or time.time() - start < wait:
        ok, frame = card.nfc.targetReceive(1000, quiet=True)
        if not ok or not frame:
            continue
        rx = bytes.fromhex(frame)
        # --- ISO 14443-3 anticollision (as emulateuid) ---
        if rx == b"\x52" or (rx == b"\x26" and not halted):       # WUPA / REQA
            halted = False
            level = 0
            activated = False
            send(atqa)
            continue
        if len(rx) == 4 and rx[:2] == b"\x50\x00":                 # HLTA
            halted = True
            continue
        if len(rx) == 2 and level < len(levels) and rx == bytes([levels[level][0], 0x20]):
            send(levels[level][1])                                 # ANTICOL: UID CLn + BCC
            continue
        if len(rx) == 9 and level < len(levels) and rx[0] == levels[level][0] and rx[1] == 0x70 \
                and rx[2:7] == levels[level][1]:
            send(levels[level][2])                                 # SELECT: SAK + CRC (already appended)
            level += 1
            if level == len(levels):
                activated = True
                print("  %.3f selected as %s" % (time.time(), uid.hex().upper()))
            continue
        # --- ISO 14443-4 (T=CL), we are the card ---
        if activated and rx and rx[0] == 0xE0:                     # RATS
            print("  %.3f RATS %s -> ATS %s" % (time.time(), frame, ATS.hex().upper()))
            send(ATS, crc=True)
            continue
        if activated and rx and (rx[0] & 0xC0) == 0x00:            # I-block (command APDU)
            body = rx[:-2] if len(rx) >= 2 else rx                 # strip CRC
            pcb = body[0]
            inf = body[1:]                                         # no CID negotiated (TC1=00)
            apdu = inf.hex().upper()
            resp = responder(apdu)
            print("  %.3f << %s   >> %s" % (time.time(), apdu, resp))
            if resp is None:
                # R(NAK)? for now just drop; a real card would not. (prototype)
                continue
            rpcb = bytes([0x02 | (pcb & 0x01)])                    # I-block, echo block number
            send(rpcb + bytes.fromhex(resp), crc=True)
            continue
        if activated and rx and (rx[0] & 0xE6) == 0xF2:            # S(WTX) request
            send(bytes([0xF2]) + rx[1:2], crc=True)                # echo WTX back
            continue
        # unhandled
        key = frame[:6]
        shown[key] = shown.get(key, 0) + 1
        if rx != b"\x26" and shown[key] <= 3:
            print("  %.3f rx %s (unhandled)" % (time.time(), frame))
except KeyboardInterrupt:
    pass
print()
if relay_reader is not None:
    try:
        relay_reader.powerOff()
        relay_reader.deconfigure()
    except Exception:
        pass
card.shutdown()
