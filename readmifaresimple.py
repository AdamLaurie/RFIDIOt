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
import time
import json
# import string
import rfidiot

json_output = None
verbose = 0
reset = False
copy = False


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
KEYTYPES = ["BB", "AA"] #  "FF"]
DEFAULT_KEYTYPE = "BB"
BLOCKS_PER_SECT = 4
START_BLOCK = 0
END_BLOCK = 63
RESET_DATA = "00000000000000000000000000000000"
RESET_TRAILER = "FFFFFFFFFFFFFF078069FFFFFFFFFFFF"


def print_mihelp():
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

trykey = KEYS

def read_mifare_simple(**kwargs):

    #  THIS GLOBAL SHOULD NOT BE NEEDED
    # global trykey, trykeytype, CloneData

    startblock = kwargs.get('startblock', START_BLOCK)
    endblock = kwargs.get('endblock', END_BLOCK)
    mi_key = kwargs.get('key', DEFAULT_KEY)
    mi_keytype = kwargs.get('keytype', DEFAULT_KEYTYPE)
    reset = kwargs.get('reset', False)
    copy = kwargs.get('copy', False)
    trykey = kwargs.get('trykey', KEYS)
    trykeytype = kwargs.get('trykeytype', KEYTYPES)

    blocksread = 0
    blockslocked = 0
    lockedblocks = []
    CloneData = []
    j_blks = None


    card.info("readmifaresimple v0.1h")

    if not card.select():
        card.waitfortag("waiting for Mifare TAG...")

    if not reset:
        json_data = kwargs.get('json_data', None)
        if json_data:
            json_data['UID'] = card.uid
            j_blks = json_data['Blocks']
        print(f"  Card ID: {card.uid}")
        print()
        print(f"    Reading from {startblock:02d} to {endblock:02d}, key {mi_key} ({mi_keytype})\n")

    # see if key is an abbreviation
    # if so, only need to set mi_keytype and login will use transport keys
    #for d in ["AA", "BB", "FF"]:
    #    if mi_key == d:
    #        mi_keytype = mi_key
    #        mi_key = ""
    if mi_key in ["AA", "BB", "FF"]:
        mi_keytype = mi_key
        mi_key = ""

    if len(mi_key) > 12:
        print("Invalid key: ", mi_key)
        sys.exit(True)


    block = startblock
    while block <= endblock and not reset:
        # locked = True
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
                # print("Login", loginblock, x, y)
                if card.login(loginblock, x, y):
                    loggedin = True
                    goodkey = y
                    goodkeytype = x
                    break
                # else:
                # clear the error
                card.select()

                # if card.ret_true():

        if loggedin:
            print(f"OK {goodkey} {goodkeytype}) Data:", end="")
            # locked = False
            if card.readMIFAREblock(block):
                blocksread += 1
                # print(card.MIFAREdata, end="")
                # print(card.ReadablePrint(card.ToBinary(card.MIFAREdata)))
                print(f"{card.MIFAREdata} {card.ReadablePrint(card.ToBinary(card.MIFAREdata))}")
                CloneData += [card.MIFAREdata]
                if json_data:
                    j_blks[block] = card.MIFAREdata
            else:
                print(f"Read error: {card.errorcode} {card.get_error_str(card.errorcode)}")
        else:
            print(f"Login error: {card.errorcode} {card.get_error_str(card.errorcode)}")
            # locked = True
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
        return

    input("Place tag to be written and hit <ENTER> to proceed")

    while True:
        print()
        card.select()
        print("  Card ID: {card.uid}")
        print()
        if not reset:
            if mi_keytype == "AA":
                print(f"  KeyA will be set to {mi_key}, KeyB will be set to {otherkey}")
            else:
                print(f"  KeyA will be set to {otherkey}, KeyB will be set to {mi_key}")
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
            trykey = KEYS + [mi_key]
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
                # else:
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
                    if mi_keytype == "BB":
                        # only ACL is useful from original data
                        blockdata = RESET_TRAILER[:12] + CloneData[outblock][12:20] + mi_key
                    else:
                        # ACL plus KeyB
                        blockdata = mi_key + CloneData[outblock][12:20] + otherkey
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


# work in progress
if __name__ == '__main__':


    # f_args = {}

    try:
        card = rfidiot.card
    except:
        print("Couldn't open reader!")
        sys.exit(False)

    args = rfidiot.args
    # print("rfidiot.args=", args)

    # chelp = rfidiot.chelp

    if rfidiot.chelp or len(args) > 6:
        print_mihelp()

    call_args = {}

    if card.json:
        json_output = call_args['json_data'] = {
            'Date': time.ctime(),
            'Blocks': {}
        }
    print("json_output", json_output)


    # set options
    # argv[0] RESET [START_BLOCK END_BLOCK] [KeyA [KeyB]]
    # argv[0] COPY  [START_BLOCK END_BLOCK] [KeyA [KeyB]]

    if args:

        x = args[-1].upper()
        if x == "RESET":
            call_args['reset'] = True
            args.pop()
        elif x == "COPY":
            call_args['copy'] = True
            args.pop()

    if args:

        if len(args) < 2:
            print("expecting additional args")
            sys.exit(True)

        if args[0] and args[0].isdigit():  # is arg a block range
            try:
                call_args['startblock'] = int(args.pop(0))
                call_args['endblock'] = int(args.pop(0))
            except ValueError:
                print("Error parsing start/end blocks")
                sys.exit(True)


    if args:
        # print("2 args", args)
        newkey = args.pop(0).upper()
        call_args['key'] = newkey
        if newkey not in KEYS:
            call_args['trykey'] = [newkey] + KEYS

    if args:
        # print("3 args", args)
        new_keytype = args.pop(0).upper()
        if new_keytype in KEYTYPES:
            KEYTYPES.remove(new_keytype)
        call_args['trykeytype'] = [new_keytype] + KEYTYPES

    if args and copy:
        # print("4 args", args)
        otherkey = args.pop()

    read_mifare_simple(**call_args)

    # if json_output:
    #    json.dump(json_output, sys.stdout, indent=2, separators=(',', ': '))

    sys.exit(False)
