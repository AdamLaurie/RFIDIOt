#!/usr/bin/python


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
from Crypto.Cipher import DES3
from Crypto.Cipher import DES

def HexArray(data):
	# first check array is all hex digits
	try:
		int(data,16)
	except:
		return False, []
	# check array is 4 hex digit pairs
	if len(data) != 12:
		return False, []
	# now break into array of hex pairs
	out= []
	for x in range(0,len(data),2):
		out.append(data[x:x+2])
	return True, out

### main ###
print('mifarekeys v0.1b')

if len(sys.argv) != 3:
	print
	print "Usage:"
	print "\t%s <KeyA> <KeyB>" % sys.argv[0]
	print
	print "\tCreate MifarePWD for access to Mifare protected memory on Dual Interface IC"
	print "\t(JCOP) cards. Output is DKeyA, DKeyB and MifarePWD. DKeyA and DKeyB are used as"
	print "\tthe DES3 keys to generate MifarePWD with an IV of (binary) '00000000', a"
	print "\tChallenge of (also binary) '00000000', and a key of DKeyA+DKeyB+DKeyA."
	print
	print "\tExample:"
	print
	print "\tUsing KeyA of A0A1A2A3A4A5 and KeyB of B0B1B2B3B4B5 should give the result:"
	print
	print "\t\tDKeyA:        40424446484A7E00"
	print "\t\tDKeyB:        007E60626466686A"
	print
  	print "\t\tMifarePWD:    8C7F46D76CE01266"
	print
	sys.exit(True)

# break keyA and keyB into 2 digit hex arrays
ret, keyA= HexArray(sys.argv[1])
if not ret:
	print "Invalid HEX string:", sys.argv[1]
	sys.exit(True)
ret, keyB= HexArray(sys.argv[2])
if not ret:
	print "Invalid HEX string:", sys.argv[2]
	sys.exit(True)

# now expand 48 bit Mifare keys to 64 bits for DES by adding 2 bytes
# one is all zeros and the other is derived from the 48 Mifare key bits

### KeyA ###
# first left shift 1 to create a 0 trailing bit (masked to keep it a single byte)
newkeyA= ''
for n in range(6):
	newkeyA += "%02X" % ((int(keyA[n],16) << 1) & 0xff)
# now create byte 6 from bit 7 of original bytes 0-5, shifted to the correct bit position
newkeyAbyte6= 0x00
for n in range(6):
	newkeyAbyte6 |= ((int(keyA[n],16) >> n + 1) & pow(2,7 - (n + 1)))
newkeyA += "%02X" % newkeyAbyte6
# and finally add a 0x00 to the end
newkeyA += '00'
print
print "  DKeyA:       ", newkeyA

### KeyB ###
# now do keyB, which is basically the same but starting at byte 2 and prepending new bytes
newkeyB= '00'
# now create byte 1 from bit 7 of original bytes 0-5, shifted to the correct bit position, which is
# the reverse of byte6 in KeyA
newkeyBbyte1= 0x00
for n in range(6):
	newkeyBbyte1 |= ((int(keyB[n],16) >> 7 - (n + 1)) & pow(2,n + 1))
newkeyB += "%02X" % newkeyBbyte1
# left shift 1 to create a 0 trailing bit (masked to keep it a single byte)
for n in range(6):
	newkeyB += "%02X" % ((int(keyB[n],16) << 1) & 0xff)
print "  DKeyB:       ", newkeyB

# now create triple-DES key
deskeyABA= ''
# build key MSB first
for n in range(len(newkeyA+newkeyB+newkeyA)-2,-2,-2):
	deskeyABA += chr(int((newkeyA+newkeyB+newkeyA)[n:n + 2],16))
des3= DES3.new(deskeyABA,DES.MODE_CBC,'\0\0\0\0\0\0\0\0')
mifarePWD= des3.encrypt('\0\0\0\0\0\0\0\0')
# reverse LSB/MSB for final output
mifarePWDout= ''
for n in range(len(mifarePWD)-1,-1,-1):
	mifarePWDout += "%02X" % int(ord(mifarePWD[n]))
print
print "  MifarePWD:   ", mifarePWDout
print
