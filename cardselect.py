#!/usr/bin/python3
#  cardselect.py - select card and display ID
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

try:
    card = rfidiot.card
except:
    print("Couldn't open reader!")
    sys.exit(True)

args = rfidiot.args

card.info("cardselect v3.1a")
# force card type if specified
if len(args) == 1:
    card.settagtype(args[0])
else:
    card.settagtype(card.ALL)

if card.select():
    print("    Card ID: " + card.uid)
    if card.readertype == card.READER_PCSC:
        print("    Type: " + card.pcsc_tag_type())
        print("    ATR: " + card.pcsc_atr)
    elif card.readertype == card.READER_LIBNFC and card.sel_res:
        print("    ATQA: " + card.sens_res + "   SAK: " + card.sel_res)
        print("    Type: ISO 14443A - " + card.iso14443a_type())
        # ISO 14443-4 cards answer SELECT with an ATS; storage cards do not
        if card.atr:
            print("    ATS: " + card.atr)
else:
    if card.errorcode:
        print("    " + card.get_error_str(card.errorcode))
    else:
        print("    No card present")
        sys.exit(True)
sys.exit(False)
