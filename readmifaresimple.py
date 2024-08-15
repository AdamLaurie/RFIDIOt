#!/usr/bin/python3
#  readmifaresimple.py - read all sectors from a mifare tag
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
# import time
# import string
import rfidiot

try:
    card = rfidiot.card
except:
    print("Couldn't open reader!")
    sys.exit(False)

args = rfidiot.args
chelp = rfidiot.help

blocksread = 0
blockslocked = 0
lockedblocks = []
DEFAULT_KEY = "FFFFFFFFFFFF"
KEYS = [
    "FFFFFFFFFFFF",
    "A0A1A2A3A4A5",
    "B0B1B2B3B4B5",
    "000000000000",
    "ABCDEF012345",
    "4D3A99C351DD",
    "1A982C7E459A",
    "D3F7D3F7D3F7",
    "AABBCCDDEEFF",
]
KEYTYPES = ["AA", "BB", "FF"]
DEFAULT_KEYTYPE = "AA"
BLOCKS_PER_SECT = 4
START_BLOCK = 0
END_BLOCK = 63
CloneData = []
RESET_DATA = "00000000000000000000000000000000"
RESET_TRAILER = "FFFFFFFFFFFFFF078069FFFFFFFFFFFF"

if chelp or len(args) > 6:
    print(sys.argv[0] + " - read mifare tags")
    print("Usage: " + sys.argv[0] + " [START BLOCK] [END BLOCK] [KEY] [KEYTYPE] [COPY|RESET]")
    print()
    print("\tRead Mifare sector numbers [START BLOCK] to [END BLOCK], using")
    print("\t[KEY] to authenticate. Keys can be truncated to 'AA' for transport")
    print("\tkey 'A0A1A2A3A4A5', 'BB' for transport key 'B0B1B2B3B4B5' or 'FF'")
    print("\tfor transport key 'FFFFFFFFFFFF'.")
    print()
    print("\tSTART BLOCK defaults to 0 and END BLOCK to 63. If not specified, KEY")
    print("\tdefaults to 'FFFFFFFFFFFF', and KEYTYPE defaults to 'AA'. All known")
    print("\talternative keys are tried in the event of a login failure.")
    print()
    print("\tIf the option 'RESET' is specified, the card will be programmed to")
    print("\tfactory defaults after reading.")
    print()
    print("\tIf the option 'COPY' is specified, a card will be programmed with")
    print("\twith the data blocks read (note that block 0 cannot normally be written)")
    print()
    sys.exit(True)

card.info("readmifaresimple v0.1h")

if not card.select():
    card.waitfortag("waiting for Mifare TAG...")

# set options

reset = False
copy = False

try:
    if args[4] == "RESET":
        reset = True
except:
    pass

try:
    if args[4] == "COPY":
        copy = True
except:
    pass

if copy:
    try:
        otherkey = args[5]
    except:
        pass

try:
    keytype = args[3].upper()
    KEYTYPES.remove(keytype)
    trykeytype = [keytype] + KEYTYPES
except:
    keytype = DEFAULT_KEYTYPE
    trykeytype = KEYTYPES

try:
    key = args[2].upper()
    trykey = [key] + KEYS
except:
    key = DEFAULT_KEY
    trykey = KEYS

try:
    endblock = int(args[1])
except:
    endblock = END_BLOCK

try:
    startblock = int(args[0])
except:
    startblock = 0

if not reset:
    print(f"  Card ID: {card.uid}")
    print()
    print(f"    Reading from {startblock:02d} to {endblock:02d}, key {key} ({keytype})\n")
# see if key is an abbreviation
# if so, only need to set keytype and login will use transport keys
for d in ["AA", "BB", "FF"]:
    if key == d:
        keytype = key
        key = ""

if len(key) > 12:
    print("Invalid key: ", key)
    sys.exit(True)

block = startblock
while block <= endblock and not reset:
    locked = True
    print("    Block %03i:" % block, end="")
    # ACG requires a login only to the base 'sector', so block number must be divided
    # by BLOCKS_PER_SECT
    if card.readertype == card.READER_ACG:
        loginblock = block / BLOCKS_PER_SECT
    else:
        loginblock = block
    loggedin = False
    for y in trykey:
        if loggedin:
            break
        for x in trykeytype:
            if card.login(loginblock, x, y):
                loggedin = True
                goodkey = y
                goodkeytype = x
                break
            else:
                # clear the error
                card.select()

    if loggedin:
        print(f"OK {goodkey} {goodkeytype}) Data:", end="")
        locked = False
        if card.readMIFAREblock(block):
            blocksread += 1
            print(card.MIFAREdata, end="")
            print(card.ReadablePrint(card.ToBinary(card.MIFAREdata)))
            CloneData += [card.MIFAREdata]
        else:
            print(f"Read error: {card.errorcode} {card.get_error_str(card.errorcode)}")
    else:
        print(f"Login error: {card.errorcode} {card.get_error_str(card.errorcode)}")
        locked = True
        blockslocked += 1
        lockedblocks.append(block)
        # ACG requires re-select to clear error condition after failed login
        if card.readertype == card.READER_ACG:
            card.select()
    block += 1

if not reset:
    print()
    print(f"  Total blocks read: {blocksread}")
    print(f"  Total blocks locked: {blockslocked}")
    if blockslocked > 0:
        print("  Locked block numbers:", lockedblocks)
    print()

if not reset and not copy:
    sys.exit(False)

input("Place tag to be written and hit <ENTER> to proceed")

while True:
    print()
    card.select()
    print("  Card ID: {card.uid}")
    print()
    if not reset:
        if keytype == "AA":
            print(f"  KeyA will be set to {key}, KeyB will be set to {otherkey}")
        else:
            print(f"  KeyA will be set to {otherkey}, KeyB will be set to {key}")
    else:
        print("  KeyA will be set to FFFFFFFFFFFF, KeyB will be set to FFFFFFFFFFFF")
    print()
    x = input("  *** Warning! This will overwrite TAG! Proceed (y/n) or <ENTER> to select new TAG? ").upper()
    if x == "N":
        sys.exit(False)
    if x == "Y":
        print()
        break

block = startblock
outblock = 0
while block <= endblock:
    # block 0 is not writeable
    if block == 0:
        block += 1
        outblock += 1
        continue
    print("    Block %03i: " % block, end="")
    # ACG requires a login only to the base 'sector', so block number must be divided
    # by BLOCKS_PER_SECT
    if card.readertype == card.READER_ACG:
        loginblock = block / BLOCKS_PER_SECT
    else:
        loginblock = block
    loggedin = False
    if not reset:
        # assume we're writing to a factory blank, so try default keys first
        trykey = KEYS + [key]
        trykeytype = ["AA", "BB"]
    for y in trykey:
        if loggedin:
            break
        for x in trykeytype:
            if card.login(loginblock, x, y):
                loggedin = True
                goodkey = y
                goodkeytype = x
                break
            else:
                # clear the error
                card.select()

    if loggedin:
        if (block + 1) % 4:
            if reset:
                blockdata = RESET_DATA
            else:
                blockdata = CloneData[outblock]
        else:
            if reset:
                blockdata = RESET_TRAILER
            else:
                if keytype == "BB":
                    # only ACL is useful from original data
                    blockdata = RESET_TRAILER[:12] + CloneData[outblock][12:20] + key
                else:
                    # ACL plus KeyB
                    blockdata = key + CloneData[outblock][12:20] + otherkey
        print(f"OK ({goodkey}, {goodkeytype}), writing: {blockdata}", end="")
        if card.writeblock(block, blockdata):
            print("OK")
        else:
            print(f"Write error: {card.errorcode} {card.get_error_str(card.errorcode)}")
    else:
        print(f"Login error: {card.errorcode} {card.get_error_str(card.errorcode)}")
        # ACG requires re-select to clear error condition after failed login
        if card.readertype == card.READER_ACG:
            card.select()
    block += 1
    outblock += 1
sys.exit(False)
