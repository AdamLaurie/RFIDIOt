#!/usr/bin/python3
#  readtag.py - read all sectors from a standard tag
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
import rfidiot

if __name__ == '__main__':

    try:
        card = rfidiot.card
    except:
        print("Couldn't open reader!")
        sys.exit(True)

    card.info("readtag v0.1f")
    card.select()
    print(f"\nID: {card.uid}")
    print("  Data:")

    card.select()
    for x in range(255):
        # print("    Block %02x:" % x, end="")
        print(f"    Block {x:02x}:", end="")
        if card.readblock(x):
            print(card.data, card.ReadablePrint(card.ToBinary(card.data)))
        else:
            # print('read error: %s, %s' % (card.errorcode, card.ISO7816ErrorCodes[card.errorcode]))
            # print("read error: {}, {}".format(card.errorcode, card.get_error_str(card.errorcode)))
            print(f"read error: {card.errorcode}, {card.get_error_str(card.errorcode)}")

    print(f"\n    Total blocks: {x}")
    if x > 0:
        sys.exit(False)
    else:
        sys.exit(True)


