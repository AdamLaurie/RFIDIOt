#!/usr/bin/python

#  froschtest.py - test frosch HTRM112 reader`
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

card.info('froschtest v0.1d')
print 
print 'Trying Hitag1: ',
if card.frosch(card.FR_HT1_Get_Snr,''):
	print card.data[:len(card.data) -2]
	if not card.select():
		print 'Select failed: ',
		print card.FROSCH_Errors[card.errorcode]
	else:
		for x in range(0,8):
			if card.readblock(x):
				print '\tBlock %02d: %s' % (x,card.data)
			else:
				print '\tBlock %0d read failed: ' % x,
				print card.FROSCH_Errors[card.errorcode]
else:
	print card.FROSCH_Errors[card.errorcode]

print 'Trying Hitag2: ',
if card.frosch(card.FR_HT2_Get_Snr_PWD,''):
	print card.data[:len(card.data) -2]
	if not card.select():
		print 'Select failed: ',
		print card.FROSCH_Errors[card.errorcode]
	else:
		for x in range(0,8):
			if card.readblock(x):
				print '\tBlock %02d: %s' % (x,card.data)
			else:
				print '\tBlock %0d read failed' % x,
				print card.FROSCH_Errors[card.errorcode]
else:
	print card.FROSCH_Errors[card.errorcode]

print 'Trying Hitag2 Public A (Unique / Miro): ',
if card.frosch(card.FR_HT2_Read_Miro,''):
	print card.data
else:
	print card.FROSCH_Errors[card.errorcode]

print 'Trying Hitag2 Public B (FDX-B): ',
if card.frosch(card.FR_HT2_Read_PublicB,''):
	print 'Raw: ' + card.data,
	print 'ID: ' + card.FDXBID128BitDecode(card.ToBinaryString(card.ToBinary(card.data)))
	card.FDXBIDPrint(card.FDXBID128BitDecode(card.ToBinaryString(card.ToBinary(card.data))))
else:
	print card.FROSCH_Errors[card.errorcode]
os._exit(False)
