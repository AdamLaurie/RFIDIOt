#!/usr/bin/python

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


import rfidiot
import sys
import random
import string
import os

try:
        card= rfidiot.card
except:
	print "Couldn't open reader!"
        os._exit(True)

args= rfidiot.args
help= rfidiot.help

card.info('writemifare1k v0.1f')
card.select()
print 'Card ID: ' + card.uid
while True:
	x= string.upper(raw_input('\n*** Warning! This will overwrite all data blocks! Proceed (y/n)? '))
	if x == 'N':
		os._exit(False)
	if x == 'Y':
		break

sector = 1
while sector < 0x10:
        for type in ['AA', 'BB', 'FF']:
                card.select()
		print ' sector %02x: Keytype: %s' % (sector, type),
                if card.login(sector,type,'FFFFFFFFFFFF'):
			for block in range(3):
                		print '\n  block %02x: ' % ((sector * 4) + block),
				if len(args) == 1:
					data= args[0]
				else:
					data = '%032x' % random.getrandbits(128)
                        	print 'Data: ' + data,
				if card.writeblock((sector * 4) + block,data):
					print ' OK'
                		elif card.errorcode:
                        		print 'error %s %s' % (card.errorcode , card.ISO7816ErrorCodes[card.errorcode])
		elif type == 'FF':
				print 'login failed'
               	print '\r',
                sys.stdout.flush()           
        sector += 1
	print
print
os._exit(False)
