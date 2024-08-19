#!/usr/bin/python3
#  multiselect.py - continuously select card and display ID
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

try:
    import rfidiot
    card = rfidiot.card
except:
    print("Couldn't open reader!")
    sys.exit(True)

args = rfidiot.args

card.info("multiselect v0.1n")

# force card type if specified
if len(args) == 1:
    if not card.settagtype(args[0]):
        print("Could not set tag type")
        sys.exit(True)
else:
    card.settagtype(card.ALL)

while 42:
    if card.select("A") or card.select("B"):
        print("    Tag ID: " + card.uid, end="")
        if card.readertype == card.READER_FROSCH and card.tagtype == card.HITAG2 and card.tagmode == card.HITAG2_PASSWORD:
            print("    Tag Type: Hitag2 (Password mode)")
        if card.readertype == card.READER_FROSCH and card.tagtype == card.HITAG2 and card.tagmode == card.HITAG2_CRYPTO:
            print("    Tag Type: Hitag2 (Crypto mode)")
        if card.readertype == card.READER_ACG and card.readername.find("LFX") == 0:
            print("    Tag Type:" + card.LFXTags[card.tagtype])
        else:
            print()
    else:
        print("    No card present\r", end="")
        sys.stdout.flush()
