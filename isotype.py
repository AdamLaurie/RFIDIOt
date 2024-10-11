#!/usr/bin/python3
#  isotype.py - determine ISO tag type
#
#  Adam Laurie <adam@algroup.co.uk>
#  http://rfidiot.org/
#
#  This code is copyright (c) Adam Laurie, 2006, All rights reserved.
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
##  import string
import rfidiot

try:
    card = rfidiot.card
except:
    print("Couldn't open reader!")
    sys.exit(True)


card.info("isotype v0.1n")

typed = 0
if card.readertype == card.READER_ACG:
    for command, cardtype in card.ISOTags.items():
        if not card.settagtype(command):
            print("Could not test for card type: " + cardtype)
            continue
        if card.select():
            print("     ID: " + card.uid)
            print("       Tag is " + cardtype)
            typed = True
            if command == card.ISO15693:
                print("         Manufacturer:", end="")
                try:
                    print(card.ISO7816Manufacturer[card.uid[2:4]])
                except:
                    print("Unknown (%s)" % card.uid[2:4])

    for command, cardtype in card.ISOTagsA.items():
        if not card.settagtype(command):
            print("Could not reset reader to " + cardtype + "!")
            sys.exit(True)
if card.readertype == card.READER_PCSC:
    if card.select():
        print("     ID: " + card.uid)
        print("       Tag is " + card.tagtype)
        # if string.find(card.tagtype, "ISO 15693") >= 0:
        if "ISO 15693" in card.tagtype:
            print("         Manufacturer:", end="")
            try:
                print(card.ISO7816Manufacturer[card.uid[2:4]])
            except:
                print(f"Unknown ({card.uid[2:4]})")
        typed = True
        print()
        print()
        if not card.readersubtype == card.READER_ACS:
            card.PCSCPrintATR(card.pcsc_atr)
    else:
        print(card.get_error_str(card.errorcode))
        sys.exit(True)
if card.readertype == card.READER_LIBNFC:
    if card.select("A"):
        print("     ID: " + card.uid)
        if card.atr:
            print("     ATS: " + card.atr)
        print("       Tag is ISO 14443A")
        typed = True
    if card.select("B"):
        print("   PUPI: " + card.pupi)
        print("    APP: " + card.appdata)
        print("  PROTO: " + card.protocol)
        print("    CID: " + card.cid)
        print("       Tag is ISO 14443B")
        typed = True
    if card.select("ICLASS"):
        print("     ID: " + card.uid)
        print("       Tag is ICLASS")
        typed = True
    if card.select("JEWEL"):
        print("SENSRES: " + card.btsensres)
        print("     ID: " + card.btid)
        print("       Tag is JEWEL")
        typed = True
if not typed:
    print("Could not determine type")
    sys.exit(True)

sys.exit(False)
