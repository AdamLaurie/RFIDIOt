#!/usr/bin/python3
#  iclass.py - read HID iCLASS / Picopass cards via an OMNIKEY CardMan 5x21
#
#  Adam Laurie <adam@algroup.co.uk>
#  http://rfidiot.org/
#
#  This code is copyright (c) Adam Laurie, 2024, All rights reserved.
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
#  iCLASS/Picopass crypto lineage: holiman/loclass + ColdHeat/iclass; the
#  OMNIKEY secured-session transport is reverse-engineered from HID's
#  SCardCLICCTransmit (see rfidiot/iclass_omnikey.py).

import sys

# default reader key slot (0x21 = OMNIKEY KMDC, pre-loaded default HID iCLASS Kd)
SLOT_KD_DEFAULT = 0x21

VERSION = "0.1a"


def usage():
    print("""iclass.py v%s - read HID iCLASS via an OMNIKEY CardMan 5x21 (pcscd + ifdokccid)

Usage:
  iclass.py [-d] [IDENTIFY]              CSN + config + AIA (standard mode, no auth)
  iclass.py [-d] DUMP [start] [end]      authenticated secured dump (default blocks 0..0x1F)
  iclass.py [-d] READ <block>            authenticated secured read of one block
  iclass.py [-d] DECRYPT                  dump app1, 3DES-decrypt credential, decode PACS/Wiegand
  iclass.py [-d] ... SLOT <hex>          reader key slot for auth (default 0x%02X = default HID Kd)
  iclass.py [-d] ... -k <hexkey>         HID 3DES transport key for DECRYPT (32 hex chars)

  -d    debug (dump the raw escape frames)

DECRYPT needs the 16-byte HID iCLASS transport key (NOT shipped - same rule as
passport MRZs): give it via -k, $RFIDIOT_ICLASS_DECRYPTKEY, or
~/.rfidiot/iclass_decryptionkey.bin (16 raw bytes, the pm3 name/location).

Place the iCLASS card on the OMNIKEY contactless slot.  NB: iCLASS is NOT
accessible over standard PC/SC - this tool needs HID's ifdokccid driver and
pcscd running.  Roughly ONE secured session works per physical card placement:
after a DUMP/READ the card's RF session desyncs (every command -> SW 6982, even
standard ones), so remove and re-present the card before the next run.""" % (VERSION, SLOT_KD_DEFAULT))


def _ascii(b):
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b)


def main(argv):
    debug = False
    args = list(argv)
    if "-d" in args:
        debug = True
        args.remove("-d")
    if "-h" in args or "--help" in args:
        usage()
        return 0

    # optional "-k <hexkey>" (HID transport key for DECRYPT)
    keyarg = None
    if "-k" in args:
        i = args.index("-k")
        try:
            keyarg = args[i + 1]
        except IndexError:
            print("-k needs a 32-hex-char key")
            return 1
        del args[i:i + 2]

    # parse an optional "SLOT <hex>" anywhere in the args
    slot = SLOT_KD_DEFAULT
    if "SLOT" in [a.upper() for a in args]:
        i = [a.upper() for a in args].index("SLOT")
        try:
            slot = int(args[i + 1], 16)
        except (IndexError, ValueError):
            print("SLOT needs a hex key-slot number, e.g. SLOT 21")
            return 1
        del args[i:i + 2]

    command = args[0].upper() if args else "IDENTIFY"

    # deferred so that "-h" prints this tool's usage (importing rfidiot triggers
    # its own global-option parsing / -h handling)
    from rfidiot.iclass_omnikey import (OmnikeyIClass, IClassError,
                                        load_decrypt_key, decrypt_block, decode_pacs, CRED_BLOCKS)

    # resolve the decrypt key up front so DECRYPT fails fast without a card
    deckey = None
    if command == "DECRYPT":
        try:
            deckey = load_decrypt_key(keyarg)
        except IClassError as e:
            print(e)
            return 1
        if deckey is None:
            print("No HID transport key. Supply it with -k <32hex>, "
                  "$RFIDIOT_ICLASS_DECRYPTKEY, or ~/.rfidiot/iclass_decryptionkey.bin")
            return 1

    print("iclass.py v%s" % VERSION)
    ic = OmnikeyIClass(debug=debug)
    try:
        csn = ic.open(reset=True)
    except IClassError as e:
        print("Couldn't open OMNIKEY iCLASS reader: %s" % e)
        return 1

    try:
        print("CSN:      %s" % "".join("%02X" % b for b in csn))

        if command == "IDENTIFY":
            info = ic.identify()
            cfg = info["config"]
            aia = info["aia"]
            print("Config:   %s" % ("".join("%02X" % b for b in cfg) if cfg else "(unreadable)"))
            print("AIA:      %s" % ("".join("%02X" % b for b in aia) if aia else "(unreadable)"))

        elif command == "READ":
            if len(args) < 2:
                print("READ needs a block number")
                return 1
            block = int(args[1], 0)
            ic.authenticate(slot=slot)
            data, sw = ic.read_block(block, secure=True)
            if data is None:
                print("block 0x%02X: read failed (SW=%04X)" % (block, sw or 0))
                return 1
            print("block 0x%02X: %s  %s" % (block, "".join("%02X" % b for b in data), _ascii(data)))

        elif command == "DUMP":
            start = int(args[1], 0) if len(args) > 1 else 0
            end = int(args[2], 0) if len(args) > 2 else 0x1F
            ic.authenticate(slot=slot)
            print("--- secured dump (slot 0x%02X), blocks 0x%02X..0x%02X ---" % (slot, start, end))
            for blk, data, sw in ic.dump(start, end, secure=True):
                if data is None:
                    print("  blk 0x%02X: ---------------- (SW=%04X)" % (blk, sw or 0))
                else:
                    print("  blk 0x%02X: %s  %s" % (blk, "".join("%02X" % b for b in data), _ascii(data)))

        elif command == "DECRYPT":
            ic.authenticate(slot=slot)
            print("--- app1 credential (3DES-decrypted) ---")
            block7_plain = None
            for blk in CRED_BLOCKS:
                data, sw = ic.read_block(blk, secure=True)
                if data is None:
                    print("  blk 0x%02X: ---------------- (SW=%04X)" % (blk, sw or 0))
                    continue
                plain = decrypt_block(data, deckey)
                if blk == 7:
                    block7_plain = plain
                print("  blk 0x%02X: %s -> %s  %s"
                      % (blk, "".join("%02X" % b for b in data),
                         "".join("%02X" % b for b in plain), _ascii(plain)))
            pacs = decode_pacs(block7_plain) if block7_plain else None
            if pacs:
                print("--- PACS / Wiegand ---")
                print("  format:   %s" % pacs["format"])
                print("  raw:      %d bits (0x%X)" % (pacs["bitlen"], pacs["raw"]))
                if "fc" in pacs:
                    print("  facility: %d" % pacs["fc"])
                    print("  card:     %d" % pacs["cn"])
            else:
                print("  (no decodable PACS in block 7 - wrong key, blank, or non-Wiegand credential)")
        else:
            usage()
            return 1
    except IClassError as e:
        print("iCLASS error: %s" % e)
        return 1
    finally:
        ic.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
