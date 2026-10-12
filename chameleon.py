#!/usr/bin/python3
#  chameleon.py - Proxgrind/RRG Chameleon Ultra emulator / slot loader
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
#  Configure the Chameleon Ultra's emulation slots. Unlike a PN532 it drives
#  its own anti-collision, so it can present an arbitrary 4/7/10-byte UID.

import sys

try:
    import rfidiot
    card = rfidiot.card
except Exception as e:
    print("Couldn't open reader! (%s)" % e)
    sys.exit(True)

from rfidiot import pychameleon as pc

args = rfidiot.args
chelp = rfidiot.help


def usage():
    print(sys.argv[0] + " - Chameleon Ultra emulator / slot loader")
    print()
    print("\tUsage: " + sys.argv[0] + " -R READER_CHAMELEON <COMMAND> ...")
    print()
    print("\t  INFO")
    print("\t      List all 8 slots, their emulated tag types, and the active slot.")
    print()
    print("\t  REBOOT")
    print("\t      Reboot the device via its DFU bootloader (the only reset the")
    print("\t      firmware offers; it returns to the app). There is no power-off.")
    print()
    print("\t  SLOT <n> UID <HEX> [TYPE <name>] [ATQA <HEX>] [SAK <HEX>] [ATS <HEX>]")
    print("\t      Set slot <n> (1-8) to emulate a 14443-A tag with the given UID")
    print("\t      (4, 7 or 10 bytes). TYPE defaults to MIFARE_1K. ATQA/SAK default")
    print("\t      to standard values for the UID length / type; override if needed.")
    print("\t      The slot is saved and the device is left emulating it (tag mode).")
    print()
    print("\t  SLOT <n> MFLOAD <FILE> [TYPE <name>] [UID/ATQA/SAK <HEX>]")
    print("\t      Load a raw MIFARE dump (16-byte blocks, e.g. from 'rfidiot-cli MF")
    print("\t      READ' or a full card dump) into slot <n> and emulate it. TYPE is")
    print("\t      inferred from the block count (64=1K, 20=Mini, 128=2K, 256=4K);")
    print("\t      the UID/ATQA/SAK are taken from block 0 unless overridden.")
    print()
    print("\t      TYPE is one of: " + ", ".join(sorted(pc.TAG_TYPES)))
    print()
    print("\t  Examples:")
    print("\t      " + sys.argv[0] + " -R READER_CHAMELEON INFO")
    print("\t      " + sys.argv[0] + " -R READER_CHAMELEON SLOT 8 UID 11223344")
    print("\t      " + sys.argv[0] + " -R READER_CHAMELEON SLOT 8 UID 04A1B2C3D4E5F6 TYPE NTAG_215")
    print("\t      " + sys.argv[0] + " -R READER_CHAMELEON SLOT 8 MFLOAD dump.mfd")
    print()
    sys.exit(True)


card.info("chameleon v0.1a")

if chelp or len(args) < 1:
    usage()

if card.readertype != card.READER_CHAMELEON:
    print("This tool requires a Chameleon Ultra (-R READER_CHAMELEON).")
    sys.exit(True)

cham = card.chameleon
command = args[0].upper()

if command == "INFO":
    active = cham.get_active_slot()
    slots = cham.get_slot_info()
    names = {v: k for k, v in pc.TAG_TYPES.items()}

    def typename(t):
        if t == 0:
            return "-"
        return names.get(t, "0x%04X" % t)

    print()
    print("  Active slot: %d" % (active + 1))
    print()
    print("    Slot  HF                 LF")
    for i, (hf, lf) in enumerate(slots):
        print("     %d    %-17s  %-10s%s"
              % (i + 1, typename(hf), typename(lf), "  <= active" if i == active else ""))
    print()
    sys.exit(False)

if command == "REBOOT":
    print()
    print("  Rebooting the Chameleon via the DFU bootloader...")
    cham.reboot()
    print("  Sent - the USB port will drop and re-enumerate; wait for it to")
    print("  reconnect before running another command.")
    sys.exit(False)

if command in ("POWERDOWN", "POWEROFF"):
    print()
    print("  The Chameleon firmware has no power-off command, so it cannot be")
    print("  powered down over USB. On battery it sleeps by itself after its")
    print("  sleep timeout; use REBOOT to force a reset, or unplug it.")
    sys.exit(True)

if command == "SLOT":
    if len(args) < 4:
        usage()
    try:
        slot = int(args[1])
    except ValueError:
        print("  Slot must be a number 1-%d" % pc.NUM_SLOTS)
        sys.exit(True)
    if not 1 <= slot <= pc.NUM_SLOTS:
        print("  Slot must be 1-%d" % pc.NUM_SLOTS)
        sys.exit(True)
    slot_fw = slot - 1

    # remaining args are KEY VALUE pairs
    rest = args[2:]
    if len(rest) % 2:
        usage()
    opts = {}
    for i in range(0, len(rest), 2):
        opts[rest[i].upper()] = rest[i + 1]

    if "MFLOAD" in opts:
        filename = opts["MFLOAD"]
        try:
            with open(filename, "rb") as f:
                dump = f.read()
        except OSError as e:
            print("  Could not read dump '%s': %s" % (filename, e))
            sys.exit(True)
        if not dump or len(dump) % 16:
            print("  Dump length %d is not a multiple of 16 (MIFARE block size)" % len(dump))
            sys.exit(True)
        nblocks = len(dump) // 16

        # tag type: explicit TYPE, else infer from the dump's block count
        if "TYPE" in opts:
            type_name = opts["TYPE"].upper()
            if type_name not in pc.TAG_TYPES:
                print("  Unknown TYPE '%s'. One of: %s" % (type_name, ", ".join(sorted(pc.TAG_TYPES))))
                sys.exit(True)
        else:
            type_name = cham.type_from_blockcount(nblocks)
        tag_type = pc.TAG_TYPES[type_name]

        # anti-collision from block 0: [UID 0-3][BCC][SAK][ATQA 0-1][manuf 8..15]
        block0 = dump[0:16]
        uid = bytes.fromhex(opts["UID"]) if "UID" in opts else block0[0:4]
        sak = bytes.fromhex(opts["SAK"]) if "SAK" in opts else block0[5:6]
        atqa = bytes.fromhex(opts["ATQA"]) if "ATQA" in opts else block0[6:8]

        print()
        print("  Loading %d blocks from %s into slot %d:" % (nblocks, filename, slot))
        print("    Type: %s (0x%04X)" % (type_name, tag_type))
        print("    UID : %s   ATQA: %s   SAK: %s"
              % (uid.hex().upper(), atqa.hex().upper(), sak.hex().upper()))
        if nblocks < 64 and type_name == "MIFARE_1K":
            print("    (partial dump: %d of 64 blocks - unloaded sectors keep the slot default)" % nblocks)
        print()

        try:
            cham.emulate_mfload(slot_fw, dump, tag_type, uid, atqa, sak)
        except pc.ChameleonError as e:
            print("  Failed: %s" % e)
            sys.exit(True)

        print("  OK - slot %d loaded (%d blocks) and now emulating (tag mode)." % (slot, nblocks))
        sys.exit(False)

    if "UID" not in opts:
        print("  SLOT requires UID or MFLOAD (EM410X not yet implemented)")
        sys.exit(True)

    try:
        uid = bytes.fromhex(opts["UID"])
    except ValueError:
        print("  UID must be hex")
        sys.exit(True)
    if len(uid) not in (4, 7, 10):
        print("  UID must be 4, 7 or 10 bytes (got %d)" % len(uid))
        sys.exit(True)

    type_name = opts.get("TYPE", "MIFARE_1K").upper()
    if type_name not in pc.TAG_TYPES:
        print("  Unknown TYPE '%s'. One of: %s" % (type_name, ", ".join(sorted(pc.TAG_TYPES))))
        sys.exit(True)
    tag_type = pc.TAG_TYPES[type_name]

    # SAK/ATQA default to standard values for the type / UID length (override if a
    # specific tag differs). ATQA's first byte carries the UID-size/cascade bits.
    sak = bytes.fromhex(opts["SAK"]) if "SAK" in opts else cham.default_sak(type_name)
    atqa = bytes.fromhex(opts["ATQA"]) if "ATQA" in opts else cham.default_atqa(len(uid))
    ats = bytes.fromhex(opts.get("ATS", ""))

    if len(sak) != 1 or len(atqa) != 2:
        print("  SAK must be 1 byte and ATQA 2 bytes")
        sys.exit(True)

    print()
    print("  Configuring slot %d:" % slot)
    print("    Type: %s (0x%04X)" % (type_name, tag_type))
    print("    UID : %s" % uid.hex().upper())
    print("    ATQA: %s   SAK: %s%s"
          % (atqa.hex().upper(), sak.hex().upper(), ("   ATS: " + ats.hex().upper()) if ats else ""))
    print()

    try:
        cham.emulate_14a(slot_fw, uid, atqa, sak, tag_type, ats)
    except pc.ChameleonError as e:
        print("  Failed: %s" % e)
        sys.exit(True)

    print("  OK - slot %d saved and now emulating (tag mode)." % slot)
    sys.exit(False)

print("  Unknown command:", command)
usage()
