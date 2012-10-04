#!/usr/bin/python

#  readmifare1k.py - read all sectors from a mifare standard tag
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
import os

try:
        card= rfidiot.card
except:
	print "Couldn't open reader!"
        os._exit(True)

card.info('readmifare1k v0.1j')
card.select()
print 'Card ID: ' + card.uid

blocksread= 0
blockslocked= 0
lockedblocks= []

for type in ['AA', 'BB', 'FF']:
	card.select()
	if card.login(0,type,''):
		if card.readMIFAREblock(0):
			card.MIFAREmfb(card.MIFAREdata)
		else:
			print 'Read error: %s %s' % (card.errorcode , card.ISO7816ErrorCodes[card.errorcode])
			os._exit(True)
		print "\nMIFARE data (keytype %s):" % type
		print "\tSerial number:\t\t%s\n\tCheck byte:\t\t%s\n\tManufacturer data:\t%s" % (card.MIFAREserialnumber, card.MIFAREcheckbyte, card.MIFAREmanufacturerdata)
print

sector = 1
while sector < 16:
	locked= True
        for type in ['AA', 'BB', 'FF']:
                print ' sector %02x: Keytype: %s' % (sector,type),
                card.select()
                if card.login(sector * 4,type,''):
			locked= False
			blocksread += 1
			print 'Login OK. Data:'
			print
			print ' ',
			for block in range(4):
				# card.login(sector,type,'')
				if card.readMIFAREblock((sector * 4) + block):
					print card.MIFAREdata,
		                	sys.stdout.flush()           
				else:
					print 'Read error: %s %s' % (card.errorcode , card.ISO7816ErrorCodes[card.errorcode])
					os._exit(True)
			print
			card.MIFAREkb(card.MIFAREdata)
			print "  Access Block User Data Byte: " + card.MIFAREaccessconditionsuserbyte
			print
			print "\tKey A (non-readable):\t%s\n\tKey B:\t\t\t%s\n\tAccess conditions:\t%s" % (card.MIFAREkeyA, card.MIFAREkeyB, card.MIFAREaccessconditions)
			print "\t\tMIFAREC1:\t%s\n\t\tMIFAREC2:\t%s\n\t\tMIFAREC3:\t%s" % (hex(card.MIFAREC1)[2:], hex(card.MIFAREC2)[2:], hex(card.MIFAREC3)[2:])
			print "\t\tMIFAREblock0AC: " + card.MIFAREblock0AC
			print "\t\t\t" + card.MIFAREACDB[card.MIFAREblock0AC]
			print "\t\tMIFAREblock1AC: " + card.MIFAREblock1AC
			print "\t\t\t" + card.MIFAREACDB[card.MIFAREblock1AC]
			print "\t\tMIFAREblock2AC: " + card.MIFAREblock2AC
			print "\t\t\t" + card.MIFAREACDB[card.MIFAREblock2AC]
			print "\t\tMIFAREblock3AC: " + card.MIFAREblock3AC
			print "\t\t\t" + card.MIFAREACKB[card.MIFAREblock3AC]
			print
			continue
		elif card.errorcode != '':
			print 'Login Error: %s %s' % (card.errorcode , card.ISO7816ErrorCodes[card.errorcode])
		elif type == 'FF':
			print 'Login failed'
                print '\r',
		sys.stdout.flush()
	if locked:
		blockslocked += 1
		lockedblocks.append(sector)
        sector += 1
print
print '  Total blocks read: %d' % blocksread
print '  Total blocks locked: %d' % blockslocked
if lockedblocks > 0:
	print '  Locked block numbers:', lockedblocks
os._exit(False)
