#!/usr/bin/python3
#  writemifare1k.py - write all blocks on a mifare standard tag
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
import random

# import string
import os
import rfidiot

try:
    card = rfidiot.card
except:
    print("Couldn't open reader!")
    sys.exit(True)

args = rfidiot.args
chelp = rfidiot.help

card.info("writemifare1k v0.1f")
card.select()
print("Card ID: " + card.uid)
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
        print(" sector %02x: Keytype: %s" % (sector, ctype), end="")
        if card.login(sector, ctype, "FFFFFFFFFFFF"):
            for block in range(3):
                print("\n  block %02x: " % ((sector * 4) + block), end="")
                if len(args) == 1:
                    data = args[0]
                else:
                    data = "%032x" % random.getrandbits(128)
                print("Data: " + data, end="")
                if card.writeblock((sector * 4) + block, data):
                    print(" OK")
                elif card.errorcode:
                    print(f"error {card.errorcode} {card.get_error_str(card.errorcode)}")
        elif ctype == "FF":
            print("login failed")
        print("\r", end="")
        sys.stdout.flush()
    sector += 1
    print()
print()

sys.exit(False)
