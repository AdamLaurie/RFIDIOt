#!/usr/bin/python3
#  readmifare1k.py - read all sectors from a mifare standard tag
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
import json

# import os
# try to deal with segfault with no readers

import time
from smartcard.Exceptions import CardConnectionException
import rfidiot


json_output = None
verbose = 0


def read_mifare1k(card, j_out=None):

    # print(f"card.silent = {card.silent}")
    verbose = card.verbose

    if j_out:
        j_out['UID']  = card.uid
        jdata = j_out['Block']
    else:
        jdata = None

    blocksread = 0
    blockslocked = 0
    lockedblocks = []

    for ctype in ["AA", "BB", "FF"]:
        card.select()
        if card.login(0, ctype, ""):
            if card.readMIFAREblock(0):
                card.MIFAREmfb(card.MIFAREdata)
            else:
                print(f"Read error: {card.errorcode} {card.get_error_str(card.errorcode)}")
                sys.exit(True)
            if j_out:
                j_out['serialnumber'] = card.MIFAREserialnumber
                j_out['checkbyte'] = card.MIFAREcheckbyte
                j_out['manufacturerdata'] = card.MIFAREmanufacturerdata

            if not j_out or verbose:
                print(f"\nMIFARE data (keytype {ctype}):")
                print(
                    "\tSerial number:\t\t%s\n\tCheck byte:\t\t%s\n\tManufacturer data:\t%s"
                    % (
                        card.MIFAREserialnumber,
                        card.MIFAREcheckbyte,
                        card.MIFAREmanufacturerdata,
                    )
                )
                print()



    sector = 0
    while sector < 16:
        locked = True
        for ctype in ["AA", "BB", "FF"]:
            if not j_out or verbose:
                print(f"\n Sector 0x{sector:02X}: Keytype: {ctype}", end="")
            card.select()
            if card.login(sector * 4, ctype, ""):
                locked = False
                blocksread += 1
                if not j_out or verbose:
                    print(" Login OK. Data:\n")
                # print()
                # print(" ", end="")

                for block in range(4):
                    # card.login(sector,type,'')
                    if card.readMIFAREblock((sector * 4) + block):
                        # print(card.MIFAREdata, end="")
                        if j_out:
                            jdata[(sector * 4) + block] = card.MIFAREdata
                        if not j_out or verbose:
                            print('    ' + card.MIFAREdata)
                            sys.stdout.flush()
                    else:
                        # print('Read error: %s %s' % (card.errorcode , card.ISO7816ErrorCodes.get(card.errorcode, "unknown Code"))
                        print(f"Read error: {card.errorcode} {card.get_error_str(card.errorcode)}")
                        sys.exit(True)

                if not j_out or verbose:
                    print()
                    card.MIFAREkb(card.MIFAREdata)
                    print(f"  Access Block User Data Byte: {card.MIFAREaccessconditionsuserbyte}")
                    print()
                    print(
                        "    Key A (non-readable):\t%s\n\tKey B:\t\t\t%s\n\tAccess conditions:\t%s"
                        % (card.MIFAREkeyA, card.MIFAREkeyB, card.MIFAREaccessconditions)
                    )
                    print(
                        "\tMIFAREC1:\t%s\n\tMIFAREC2:\t%s\n\tMIFAREC3:\t%s"
                        % (
                            hex(card.MIFAREC1)[2:],
                            hex(card.MIFAREC2)[2:],
                            hex(card.MIFAREC3)[2:],
                        )
                    )
                    print("\tMIFAREblock0AC: " + card.MIFAREblock0AC)
                    print("\t    " + card.MIFAREACDB[card.MIFAREblock0AC])
                    print("\tMIFAREblock1AC: " + card.MIFAREblock1AC)
                    print("\t    " + card.MIFAREACDB[card.MIFAREblock1AC])
                    print("\tMIFAREblock2AC: " + card.MIFAREblock2AC)
                    print("\t    " + card.MIFAREACDB[card.MIFAREblock2AC])
                    print("\t\tMIFAREblock3AC: " + card.MIFAREblock3AC)
                    print("\t    " + card.MIFAREACKB[card.MIFAREblock3AC])
                    print()
                    continue

            # elif card.errorcode != "":
            if card.errorcode != "" and not card.silent:
                print(f"Login Error: {card.errorcode} {card.get_error_str(card.errorcode)}")
            elif ctype == "FF" and not card.silent:
                print("Login failed")
            if not j_out or verbose:
                print("\r", end="")
                sys.stdout.flush()

        if locked:
            blockslocked += 1
            lockedblocks.append(sector)
        sector += 1

    if not j_out or verbose:
        print()
        print(f"  Total blocks read: {blocksread}")
        print(f"  Total blocks locked: {blockslocked}")

        if lockedblocks:
            print("  Locked block numbers:", lockedblocks)

if __name__ == '__main__':

    try:
        card = rfidiot.card
    except ConnectionAbortedError as _e:
        print("Couldn't open reader!")
        print(_e)
        sys.exit(True)

    card.info("readmifare1k v0.1j")
    x = card.select()

    if not x:
        print("Couldn't open card!")
        sys.exit(True)

    # print(f"card.json = {card.json}")
    # print(f"card.verbose = {card.verbose}")
    # print(f"card.silent = {card.silent}")
    # time.sleep(2)

    if card.json:
        json_output = {
            'Date': time.ctime(),
            'data': {}
        }

    try:
        read_mifare1k(card, json_output)
    except CardConnectionException as _e:  # smartcard.Exceptions.CardConnectionException
        print(_e)

    if json_output:
        json.dump(json_output, sys.stdout, indent=2, separators=(',', ': '))

    sys.exit(False)
