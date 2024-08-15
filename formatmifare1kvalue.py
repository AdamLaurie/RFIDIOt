#!/usr/bin/python3
#  formatmifare1kvalue.py - format value blocks on a mifare standard tag
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

# import string
# import os
import rfidiot

try:
    card = rfidiot.card
except:
    print("Couldn't open reader!")
    sys.exit(True)

card.info("formatmifare1k v0.1c")
card.select()
print("Card ID: " + card.data)
while True:
    x = input("\n*** Warning! This will overwrite all data blocks! Proceed (y/n)? ").upper()
    if x == "N":
        sys.exit(False)
    if x == "Y":
        break

sector = 1
while sector < 0x10:
    for ctype in ["AA", "BB", "FF"]:
        card.select()
        print(f" sector {sector:02x}: Keytype: {ctype}", end=" ")
        if card.login(sector, ctype, ""):
            for block in range(3):
                print("\n  block %02x: " % ((sector * 4) + block), end=" ")
                data = "00000000"
                print("Value: " + data, end=" ")
                if card.writevalueblock((sector * 4) + block, data):
                    print(" OK")
                elif card.errorcode:
                    print("error code: " + card.errorcode)
        elif ctype == "FF":
            print("login failed")
        print("\r", end=" ")
        sys.stdout.flush()
    sector += 1
    print()
print()
