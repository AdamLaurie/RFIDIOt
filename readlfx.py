#!/usr/bin/python

#  readlfx.py - read all sectors from a LFX reader
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

# usage: readlfx [KEY]
#
#        specifiy KEY for protected tags. If not specified, TRANSPORT key will be tried.

import rfidiot
import sys
import os

try:
        card= rfidiot.card
except:
	print "Couldn't open reader!"
        os._exit(True)

args= rfidiot.args
help= rfidiot.help

Q5Mod= { '000':'Manchester',\
	 '001':'PSK 1',\
	 '010':'PSK 2',\
	 '011':'PSK 3',\
	 '100':'FSK 1 (a = 0)',\
	 '101':'FSK 2 (a = 0)',\
	 '110':'Biphase',\
	 '111':'NRZ / direct'}

card.info('readlfx v0.1m')

# force card type if specified
if len(args) > 0:
	print 'Setting tag type:', args[0]
	card.settagtype(args[0])
else:
	card.settagtype(card.ALL)
card.select()
ID= card.uid
print 'Card ID: ' + ID
print 'Tag type: ' + card.LFXTags[card.tagtype]

# set key if specified
if len(args) > 1:
	key= args[1]
else:
	key= ''

# Login to Hitag2
if card.tagtype == card.HITAG2 and card.readertype == card.READER_ACG:
	if not key:
		key= card.HITAG2_TRANSPORT_RWD
	print ' Logging in with key: ' + key
	if not card.login('','',key):
		print 'Login failed!'
		os._exit(True)

# Interpret EM4x05 ID structure
if card.tagtype == card.EM4x05:
	card.FDXBIDPrint(ID)

# Q5 cards can emulate other cards, so check if this one responds as Q5
if card.tagtype == card.EM4x02 or card.tagtype == card.Q5 or card.tagtype ==  card.EM4x05:
	print '  Checking for Q5'
	card.settagtype(card.Q5)
	card.select()
	Q5ID= card.uid
	if card.tagtype == card.Q5:
		print '    Q5 ID: ' + Q5ID
		print
		card.readblock(0)
		print '    Config Block: ',
		print card.ToHex(card.binary)
		print '    Config Binary: ',
		configbin= card.ToBinaryString(card.binary)
		print configbin
		print '          Reserved: ' + configbin[:12]
		print '       Page Select: ' + configbin[12]
		print '        Fast Write: ' + configbin[13]
		print '  Data Bit Rate n5: ' + configbin[14]
		print '  Data Bit Rate n4: ' + configbin[15]
		print '  Data Bit Rate n3: ' + configbin[16]
		print '  Data Bit Rate n2: ' + configbin[17]
		print '  Data Bit Rate n1: ' + configbin[18]
		print '  Data Bit Rate n0: ' + configbin[19]
		print ' (Field Clocks/Bit: %d)' % (2 * int(configbin[14:20],2) + 2)
		print '           Use AOR: ' + configbin[20]
		print '           Use PWD: ' + configbin[21]
		print '  PSK Carrier Freq: ' + configbin[22] + configbin[23]
		print '  Inverse data out: ' + configbin[24]
		print '        Modulation: ' + configbin[25] + configbin[26] + configbin[27] + " (%s)" % Q5Mod[configbin[25] + configbin[26] + configbin[27]]
		print '          Maxblock: ' + configbin[28] + configbin[29] + configbin[30] + " (%d)" % int (configbin[28] + configbin[29] + configbin[30],2)
		print '        Terminator: ' + configbin[31]
		print
		# Emulated ID is contained in 'traceability data'
		print '    Traceability Data 1: ',
		card.readblock(1)
		td1= card.binary
# to test a hardwired number, uncomment following line (and td2 below)
#		td1= chr(0xff) + chr(0x98) + chr(0xa6) + chr(0x4a)
		print card.ToHex(td1)
		print '    Traceability Data 2: ',
		card.readblock(2)
		td2= card.binary
# don't forget to set column parity!
#		td2= chr(0x98) + chr(0xf8) + chr(0xc8) + chr(0x06)
		print card.ToHex(td2)
		print '    Traceability Binary: ',
		tdbin= card.ToBinaryString(td1 + td2)
		print tdbin
		# traceability is broken into 4 bit chunks with even parity
		print
		print '      Header:',
		print tdbin[:9]
		print '                    Parity (even)'
		print '      D00-D03: ' + tdbin[9:13] + ' ' + tdbin[13]
		print '      D10-D13: ' + tdbin[14:18] + ' ' + tdbin[18]
		print '      D20-D23: ' + tdbin[19:23] + ' ' + tdbin[23]
		print '      D30-D33: ' + tdbin[24:28] + ' ' + tdbin[28]
		print '      D40-D43: ' + tdbin[29:33] + ' ' + tdbin[33]
		print '      D50-D53: ' + tdbin[34:38] + ' ' + tdbin[38]
		print '      D60-D63: ' + tdbin[39:43] + ' ' + tdbin[43]
		print '      D70-D73: ' + tdbin[44:48] + ' ' + tdbin[48]
		print '      D80-D83: ' + tdbin[49:53] + ' ' + tdbin[53]
		print '      D90-D93: ' + tdbin[54:58] + ' ' + tdbin[58]
		print '               ' + tdbin[59:63] + ' ' + tdbin[63] + ' Column Parity & Stop Bit'
		# reconstruct data bytes
		d0= chr(int(tdbin[9:13] + tdbin[14:18],2))
		d1= chr(int(tdbin[19:23] + tdbin[24:28],2))
		d2= chr(int(tdbin[29:33] + tdbin[34:38],2))
		d3= chr(int(tdbin[39:43] + tdbin[44:48],2))
		d4= chr(int(tdbin[49:53] + tdbin[54:58],2))
		print
		print '      Reconstructed data D00-D93 (UNIQUE ID): ',
		card.HexPrint(d0 + d1 + d2 + d3 + d4)
		# set ID to Q5ID so block reading works
		ID= Q5ID
		print
	else:
		print '    Native - UNIQUE ID: ' + card.EMToUnique(ID)

sector = 0
while sector < card.LFXTagBlocks[card.tagtype]:
        print ' sector %02x: ' % sector,
	if card.readblock(sector):
		print card.data
	else:
		print 'Read error: ' + card.errorcode
        sector += 1
print

# set reader back to all cards
card.settagtype(card.ALL)
card.select()
print
os._exit(False)
