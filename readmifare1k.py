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

# import os
# try to deal with segfault with no readers
try:
    import rfidiot

    card = rfidiot.card
except ConnectionAbortedError as _e:
    print("Couldn't open reader!")
    print(_e)
    sys.exit(True)


print("CONN")  ## PMS

card.info("readmifare1k v0.1j")
x = card.select()

if not x:
    print("Couldn't open card!")
    sys.exit(True)

print("Card ID: " + card.uid)


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

print("----")  ## PMS

sector = 1
while sector < 16:
    locked = True
    for ctype in ["AA", "BB", "FF"]:
        print(f"\n Sector 0x{sector:02X}: Keytype: {ctype}", end="")
        sys.stdout.flush()
        sys.stderr.flush()
        print("1---")
        card.select()
        sys.stdout.flush()
        sys.stderr.flush()
        print("2---")
        sys.stdout.flush()
        sys.stderr.flush()
        if card.login(sector * 4, ctype, ""):
            locked = False
            blocksread += 1
            print("Login OK. Data:\n")
            # print()
            # print(" ", end="")
            for block in range(4):
                # card.login(sector,type,'')
                if card.readMIFAREblock((sector * 4) + block):
                    # print(card.MIFAREdata, end="")
                    print('    ' + card.MIFAREdata)
                    sys.stdout.flush()
                    sys.stderr.flush()
                else:
                    # print('Read error: %s %s' % (card.errorcode , card.ISO7816ErrorCodes.get(card.errorcode, "unknown Code"))
                    print(f"Read error: {card.errorcode} {card.get_error_str(card.errorcode)}")
                    sys.exit(True)
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
        elif card.errorcode != "":
            print(f"Login Error: {card.errorcode} {card.get_error_str(card.errorcode)}")
        elif ctype == "FF":
            print("Login failed")
        print("\r", end="")
        sys.stdout.flush()
        sys.stderr.flush()

    if locked:
        blockslocked += 1
        lockedblocks.append(sector)
    sector += 1

print()
print(f"  Total blocks read: {blocksread}")
print(f"  Total blocks locked: {blockslocked}")

if lockedblocks:
    print("  Locked block numbers:", lockedblocks)
sys.exit(False)
