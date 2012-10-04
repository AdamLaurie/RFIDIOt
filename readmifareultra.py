#!/usr/bin/python

#  readmifareultra.py - read all sectors from a Ultralight tag
# 
#  Keith Howell <kch@kch.net>
#    built on the code by:
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


import rfidiot
import sys
import os

try:
        card= rfidiot.card
except:
	print "Couldn't open reader!"
        os._exit(True)

help= rfidiot.help

if help:
        print sys.argv[0] + ' - read mifare ultralight tags'
        print 'Usage: ' + sys.argv[0]
        print
	os._exit(True)

card.info('readmifareultra v0.1b')
card.waitfortag('Waiting for Mifare Ultralight...')

blocks=16

print '\n  ID: ' + card.uid
print 'Type: ' + card.tagtype

card.select()
# pull header block information from the tag
if card.readblock(0):
	sn0=card.data[0:2]
	sn1=card.data[2:4]
	sn2=card.data[4:6]
	bcc0=card.data[6:8]
else:
	print 'read error: %s' % card.errorcode

if card.readblock(1):
	sn3=card.data[0:2]
	sn4=card.data[2:4]
	sn5=card.data[4:6]
	sn6=card.data[6:8]
else:
	print 'read error: %s' % card.errorcode

if card.readblock(2):
	bcc1=card.data[0:2]
	internal=card.data[2:4]
	lock0=card.data[4:6]
	lock1=card.data[6:8]
else:
	print 'read error: %s' % card.errorcode

if card.readblock(3):
	otp0=card.data[0:2]
	otp1=card.data[2:4]
	otp2=card.data[4:6]
	otp3=card.data[6:8]
else:
	print 'read error: %s' % card.errorcode

# convert lock bytes to binary for later use
lbits0=card.ToBinaryString(card.ToBinary(lock0))
lbits1=card.ToBinaryString(card.ToBinary(lock1))
lbits=lbits1 + lbits0

y=0
plock=''
for x in range(15,-1,-1):
	plock = lbits[y:y+1] + plock
	y += 1

# show status of the OTP area on the tag
print 'OTP area is',
if int(plock[3:4]) == 1:
	print 'locked and',
else:
	print 'unlocked and',
if int(plock[0:1]) == 1:
	print 'cannot be changed'
else:
	print 'can be changed'

print 'If locked, blocks 4 through 9',
if int(plock[1:2]) == 1:
	print 'cannot be unlocked'
else:
	print 'can be unlocked'

print 'If locked, blocks 0a through 0f',
if int(plock[2:3]) == 1:
	print 'cannot be unlocked'
else:
	print 'can be unlocked'

print '\nTag Data:'
# DATA0 byte starts on page/block 4
for x in range(blocks):
	print '    Block %02x:' % x,
	if card.readblock(x):
		print card.data[:8],
		print card.ReadablePrint(card.ToBinary(card.data[:8])),
		if x > 2:
			if int(plock[x:x+1]) == 1:
				print '  locked'
			else:
				print '  unlocked'
		else:
			print '  -'
	else:
		print 'read error: %s' % card.errorcode
print

if x > 0:
	os._exit(False)
else:
	os._exit(True)
