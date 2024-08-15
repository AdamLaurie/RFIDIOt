#!/usr/bin/python3
#  copytag.py - read all sectors from a standard tag and write them back
#               to a blank
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
# import string
import rfidiot

try:
    card = rfidiot.card
except:
    print("Couldn't open reader!")
    sys.exit(True)

card.info("copytag v0.1d")
card.select()
print(f"\nID: {card.uid}")
print("  Reading:")

buffer = []

card.select()
for x in range(98):
    if card.readblock(x):
        print(f"    Block {x:02x}: {card.data}\r", end="")
        sys.stdout.flush()
        buffer.append(card.data)
    else:
        if x == 0:
            print("Read error: ", card.get_error_str(card.errorcode))
        break

if x > 0:
    print(f"\nRead {x} blocks")
    input("Remove source tag and hit <CR> to continue...")
    targettype = card.tagtype
    while 42:
        card.waitfortag("Waiting for blank tag...")
        print("ID: " + card.uid)
        if card.tagtype != targettype:
            input("Invalid tag type! Hit <CR> to continue...")
            continue
        if not card.readblock(0):
            input("Tag not readable! Hit <CR> to continue...")
            continue
        if len(card.data) != len(buffer[0]):
            print("Wrong blocksize! ({len(buffer[0])} / {len(card.data)})", end="")
            input(" Hit <CR> to continue...")
            continue
        if input("*** Warning! Data will be overwritten! Continue (y/n)?").upper() == "Y":
            break
        else:
            sys.exit(False)
    print("  Writing:")
    for n in range(x):
        # print("    Block %02x: %s\r" % (n, buffer[n]), end="")
        print(f"    Block {n:02x}: {buffer[n]}\r", end="")
        sys.stdout.flush()
        if not card.writeblock(n, buffer[n]):
            print("\nWrite failed!")
    print("\n  Verifying:")
    for n in range(x):
        # print("    Block %02x: %s" % (n, buffer[n]), end="")
        print(f"    Block {n:02x}: {buffer[n]}\r", end="")
        if not card.readblock(n) or card.data != buffer[n]:
            print("\nVerify failed!")
            sys.exit(True)
        print(" OK\r", end="")
        sys.stdout.flush()
    print()
    sys.exit(False)
else:
    print("No data!")
    sys.exit(True)
