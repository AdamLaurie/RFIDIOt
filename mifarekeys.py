#!/usr/bin/python3
#  mifarekeys.py - calculate 3DES key for Mifare access on JCOP cards
#  as per Philips Application Note AN02105
#  http://www.nxp.com/acrobat_download/other/identification/067512.pdf
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
# 22/07/08 - version 1.0 - Mifare to 3DES key mapping working, but not final MifarePWD
# 23/07/08 - version 1.1 - Fix 3DES ciphering FTW!
# 24/07/08 - version 1.2 - Add some usage text

import sys
from Crypto.Cipher import DES3, DES

_VERSION="v0.1c"

def print_help() -> None:

    print(f"""
    Usage:
    \t{sys.argv[0]} <KeyA> <KeyB>" % sys.argv[0]

    \tCreate MifarePWD for access to Mifare protected memory on Dual Interface IC
    \t(JCOP cards. Output is DKeyA, DKeyB and MifarePWD. DKeyA and DKeyB are used as)
    \tthe DES3 keys to generate MifarePWD with an IV of (binary '00000000', a)
    \tChallenge of (also binary '00000000', and a key of DKeyA+DKeyB+DKeyA.)

    \tExample:

    \tUsing KeyA of A0A1A2A3A4A5 and KeyB of B0B1B2B3B4B5 should give the result:

    \t\tDKeyA:        40424446484A7E00
    \t\tDKeyB:        007E60626466686A

    \t\tMifarePWD:    8C7F46D76CE01266
    """)


# break keyA and keyB into bytearrays


def gen_MifarePWD(keyA, keyB) -> list:
    """ calculate 3DES key for Mifare access on JCOP cards """


    # now expand 48 bit Mifare keys to 64 bits for DES by adding 2 bytes
    # one is all zeros and the other is derived from the 48 Mifare key bits

    # KeyA
    # first left shift 1 to create a 0 trailing bit (masked to keep it a single byte)
    newkeyA = bytearray()
    for n in keyA:
        newkeyA.append((n << 1) & 0xFF)
    # now create byte 6 from bit 7 of original bytes 0-5, shifted to the correct bit position
    newkeyAbyte6 = 0x00
    m = 0b01000000
    for n, b in enumerate(keyA):
        newkeyAbyte6 |= (b >> n + 1) & m
        m >>= 1
    newkeyA.append(newkeyAbyte6)
    # and finally add a 0x00 to the end
    newkeyA.append(0)

    # KeyB
    # now do keyB, which is basically the same but starting at byte 2 and prepending new bytes
    newkeyB = bytearray([0])
    # now create byte 1 from bit 7 of original bytes 0-5, shifted to the correct bit position, which is
    # the reverse of byte6 in KeyA
    newkeyBbyte1 = 0x00
    m = 0b00000010
    for n, b in enumerate(keyB):
        newkeyBbyte1 |= b >> 7 - (n + 1) & m
        m <<= 1
    newkeyB.append(newkeyBbyte1)
    # left shift 1 to create a 0 trailing bit (masked to keep it a single byte)
    for b in keyB:
        newkeyB.append((b << 1) & 0xFF)


    # now create triple-DES key
    deskeyABA = ""
    # build key MSB first
    keyABA = newkeyA + newkeyB + newkeyA
    deskeyABA = keyABA[::-1]

    des3 = DES3.new(deskeyABA, DES.MODE_CBC, b"\0\0\0\0\0\0\0\0")
    mifarePWD = des3.encrypt(b"\0\0\0\0\0\0\0\0")

    # reverse LSB/MSB for final output
    mifarePWDout = mifarePWD[::-1].hex().upper()

    # Convert to Hex
    dKeyA = newkeyA.hex().upper()
    dKeyB = newkeyB.hex().upper()
    
    return [mifarePWDout, dKeyA, dKeyB]


if __name__ == '__main__':

    print(f"mifarekeys {_VERSION}")
    if len(sys.argv) != 3:
        print_help()
        sys.exit(True)

    try:
        key_A = bytearray.fromhex(sys.argv[1])
    except ValueError:
        print("A Invalid HEX string:", sys.argv[1])
        sys.exit(True)

    try:
        key_B = bytearray.fromhex(sys.argv[2])
    except ValueError:
        print("B Invalid HEX string:", sys.argv[2])
        sys.exit(True)

    mifarePWD, dKey_A, dKey_B = gen_MifarePWD(key_A, key_B)

    print("  DKeyA:       ", dKey_A)
    print("  DKeyB:       ", dKey_B)
    print()
    print("  MifarePWD:   ", mifarePWD)
    print()
