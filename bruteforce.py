#!/usr/bin/python3
#  bruteforce.py - try random numbers to login to sector 0
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


import random
import sys

# import os
import rfidiot

try:
    card = rfidiot.card
except Exception as _e:
    print("Couldn't open reader!")
    print(_e)
    sys.exit(True)

args = rfidiot.args
chelp = rfidiot.help

card.info("bruteforce v0.1i")
card.select()
print(f"Card ID: {card.uid}")

finished = 0
tries = 0
print(f" Tries: {tries}s\r", end="")
sys.stdout.flush()

while not finished:

    tries += 1
    if tries % 10 == 0:
        print(" Tries: {tries}\r", end="")
        sys.stdout.flush()

    if len(args) == 1:
        key = args[0]
        if len(key) != 12:
            print("  Static Key must be 12 HEX characters!")
            sys.exit(True)
        print(f"Trying static key: {key}")
    else:
        key = "%012x" % random.getrandbits(48)

    for ctype in ["AA", "BB"]:
        card.select()
        if card.login(0, ctype, key):
            print(f"\nlogin succeeded after {tries} tries!")
            print("key: {ctype} {key}")
            finished = 1
            break

        # elif (
        #     card.errorcode != "X"
        #     and card.errorcode != "6982"
        #     and card.errorcode != "6200"
        # ):
        if not card.errorcode in ["X", "6982", "6200"]:
            print("\nerror!")
            print("key: " + ctype + " " + key)
            print("error code: " + card.errorcode)
            finished = 1
            break

    if finished:
        break
sys.exit(False)
