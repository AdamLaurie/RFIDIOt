#!/usr/bin/python3
#  emulateuid.py - emulate an ISO 14443-A UID of your choice (4, 7 or 10 bytes)
#  on a libnfc PN53x reader, beating the chip's hard-wired '08' first UID byte
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
#  How it works: the PN53x answers anticollision in hardware (AutoColl) from a
#  buffer holding only 3 UID bytes, always sending '08' + those 3 bytes. But
#  once AutoColl has activated it - a full select plus one following command -
#  the chip stays an activated target that relays raw frames to the host, and
#  the host can then answer REQA/WUPA, ANTICOL and SELECT itself with any UID
#  (the trick of libnfc's nfc-emulate-uid). Getting that first activation is
#  the "priming", and there are two ways:
#
#    retry (default) - the real reader primes us itself. We prime with SAK 20,
#      so its select is followed by a RATS, which breaks us out of AutoColl. We
#      never answer the RATS: the reader's activation fails, and a reader that
#      retries (PN532-based ones do) then selects again - this time answered by
#      the host, so the first UID it reports is ours.
#
#    primer (-p) - a second reader (ACR122U, TWN4 or another libnfc reader)
#      does the priming select here, so the real reader sees our UID from its
#      very first poll. BUT the activation is lost as soon as the emulator
#      loses the RF field: lifting it out of the field, or a reader that drops
#      its field (the TWN4 does at every SearchTag), releases the chip, and it
#      then answers nothing until restarted. So the primer's field must still
#      be on when the real reader's field takes over - moving the emulator
#      from one reader to another does NOT work (hardware-tested). The
#      ACR122U's own RF-off command does not drop the field enough to matter.
#
#  Readers that cycle their field before every poll (e.g. the TWN4) release
#  the activation themselves, so they always read the '08' priming UID.
#
#  Only the UID layer (ISO 14443-3 anticollision/select, HLTA) is emulated;
#  later commands (RATS, MIFARE auth, ...) are shown but not answered.

import getopt
import os
import sys
import threading
import time

import rfidiot

card = rfidiot.card
args = rfidiot.args

card.info("emulateuid v3.1a")


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
    print(sys.argv[0] + " - emulate an ISO 14443-A UID of your choice on a libnfc PN53x reader")
    print()
    print("Usage: %s [options] <UID>" % sys.argv[0])
    print()
    print("  UID is 4, 7 or 10 bytes of HEX (a 4-byte UID may not start with 88)")
    print()
    print("  Options:")
    print()
    print("    -a <ATQA>     ATQA as sent on the wire (default 0400, 4400 or 8400 by UID size)")
    print("    -k <SAK>      final SAK (default 08, MIFARE Classic 1K)")
    print("    -p <PRIMER>   prime with a second reader first (its field must stay on - see below):")
    print("                    ccid[:bus:dev]        ACR122U (direct CCID)")
    print("                    twn4[:port]           ELATEC TWN4")
    print("                    pn53x_usb:bus:dev     any libnfc reader (libnfc connstring)")
    print("    -w <SECONDS>  stop after this many seconds (default: run until Ctrl-C)")
    print()
    print("  Without -p the real reader primes us: its first activation fails (we never")
    print("  answer the RATS that SAK 20 provokes) and a reader that retries gets our UID.")
    print("  With -p the real reader sees our UID from its first poll, but the priming is")
    print("  lost the moment the emulator loses RF field (lifted out, or a reader that cycles")
    print("  its field, like the TWN4): the primer's field must overlap the real reader's.")
    print()
    print("  The emulator must be a libnfc PN53x (-f), e.g. an SCL3711. Only the UID layer")
    print("  is emulated: later commands (RATS, MIFARE auth, ...) are shown, not answered.")
    print()
    print("  Examples:")
    print()
    print("    %s -f pn53x_usb:003:011 DEADBEEF" % sys.argv[0])
    print("    %s -f pn53x_usb:003:011 -p ccid 04A1B2C3D4E5F6" % sys.argv[0])
    print()


if rfidiot.help:
    usage()
    sys.exit(False)

try:
    opts, args = getopt.getopt(args, "a:k:p:w:")
except getopt.GetoptError as e:
    print("  " + str(e))
    usage()
    sys.exit(True)

atqa = None
sak = 0x08
primer = None
wait = 0
try:
    for o, a in opts:
        if o == "-a":
            atqa = bytes.fromhex(a)
            assert len(atqa) == 2
        elif o == "-k":
            sak = int(a, 16)
            assert 0 <= sak <= 0xFF
        elif o == "-p":
            primer = a
        elif o == "-w":
            wait = float(a)
    uid = bytes.fromhex(args[0])
    assert len(uid) in (4, 7, 10)
except (ValueError, AssertionError, IndexError):
    usage()
    sys.exit(True)

if len(uid) == 4 and uid[0] == 0x88:
    print("  A 4-byte UID can't start with 88 (that is the cascade tag)")
    sys.exit(True)

if card.readertype != card.READER_LIBNFC or not hasattr(card.nfc, "initAsTarget"):
    print("  The emulator must be a libnfc PN53x reader (-f <connstring>)")
    sys.exit(True)

# per cascade level: (SEL code, UID CLn bytes + BCC, SAK for this level)
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
    level_sak = (sak & ~0x04) if final else 0x04   # bit 0x04: UID not complete
    levels.append((0x93 + 2 * n, part + bytes([bcc]), bytes([level_sak]) + crc_a(bytes([level_sak]))))

# priming identity for the chip's own AutoColl: SAK 20 makes the priming reader
# follow its select with a RATS - the command that breaks us out of AutoColl
prime_uid = "08" + os.urandom(3).hex().upper()
nt = card.nfc.make_iso14443a_target("0400", prime_uid, "20")

primed = threading.Event()


def run_primer(spec):
    "drive the primer reader until the emulator reports activation"
    try:
        if spec.lower().startswith("ccid"):
            from rfidiot.pynfc import ACR122CCID
            reader = ACR122CCID(spec)
            name = reader.LIBNFC_READER
            select = reader.selectISO14443A
            close = lambda: (reader.powerOff(), reader.deconfigure())
        elif spec.lower().startswith("twn4"):
            try:
                from rfidiot import pytwn4
            except ImportError:
                print("  primer: TWN4 support (rfidiot/pytwn4.py) is not installed")
                return
            reader = pytwn4.TWN4(spec[5:] or None)
            name = reader.readername
            select = lambda: reader.select(pytwn4.HFTAG_MIFARE)
            close = reader.close
        else:
            from rfidiot.pynfc import NFC
            reader = NFC(spec)
            name = spec
            select = reader.selectISO14443A
            close = lambda: (reader.powerOff(), reader.deconfigure())
    except Exception as e:
        print("  primer: could not open '%s': %s" % (spec, e))
        return
    print("  primer: %s" % name)
    try:
        deadline = time.time() + 15
        while not primed.is_set() and time.time() < deadline:
            seen = select()
            if seen:
                print("  primer: read %s" % (seen.uid if hasattr(seen, "uid") else seen[0]))
            time.sleep(0.2)
        # one more read: a reader that retries after its failed RATS sees our UID
        if primed.is_set():
            time.sleep(0.2)
            seen = select()
            if seen:
                print("  primer: read %s after priming" % (seen.uid if hasattr(seen, "uid") else seen[0]))
    finally:
        close()


print()
print("  Emulating UID %s (ATQA %s, SAK %02X)" % (uid.hex().upper(), atqa.hex().upper(), sak))
print("  Priming identity %s, SAK 20" % prime_uid)
print()
if primer:
    print("  Priming with %s..." % primer)
    threading.Thread(target=lambda: (time.sleep(0.3), run_primer(primer)), daemon=True).start()
else:
    print("  Waiting for the real reader to prime us (its first activation will fail)...")

ok, first = card.nfc.initAsTarget(nt, int(wait * 1000) if wait else 0)
if not ok:
    print("  Not activated (%s)" % first)
    sys.exit(True)
primed.set()
print("  %.3f primed - activated by %s, first command %s" % (time.time(), prime_uid, first or "(none)"))
if primer:
    print("  Now bring in the real reader - keep the emulator in a field: losing it")
    print("  releases the activation (Ctrl-C to stop)")
print()

# from now on the host answers anticollision itself: frames carry no CRC
card.nfc.targetHandleCRC(False)
start = time.time()
halted = False
level = 0
selects = 0
shown = {}
try:
    while not wait or time.time() - start < wait:
        ok, frame = card.nfc.targetReceive(1000, quiet=True)
        if not ok or not frame:
            continue
        rx = bytes.fromhex(frame)
        tx = None
        if rx == b"\x52" or (rx == b"\x26" and not halted):      # WUPA / REQA
            halted = False
            level = 0
            tx = atqa
        elif len(rx) == 4 and rx[:2] == b"\x50\x00":               # HLTA
            halted = True
            what = "HLTA"
        elif len(rx) == 2 and level < len(levels) and rx == bytes([levels[level][0], 0x20]):
            tx = levels[level][1]                                  # ANTICOL: UID CLn + BCC
        elif len(rx) == 9 and level < len(levels) and rx[0] == levels[level][0] and rx[1] == 0x70 \
                and rx[2:7] == levels[level][1]:
            tx = levels[level][2]                                  # SELECT: SAK + CRC
            level += 1
            if level == len(levels):
                selects += 1
                print("  %.3f selected as %s (%d)" % (time.time(), uid.hex().upper(), selects))
        else:
            what = "not handled"
        if tx is not None:
            card.nfc.targetSend(tx.hex())
        elif rx != b"\x26":                                        # halted card ignores REQA
            key = frame[:4] + "/" + what
            shown[key] = shown.get(key, 0) + 1
            if shown[key] <= 3:
                print("  %.3f rx %s (%s)" % (time.time(), frame, what))
except KeyboardInterrupt:
    pass
print()
print("  %d selects as %s" % (selects, uid.hex().upper()))
card.shutdown()
