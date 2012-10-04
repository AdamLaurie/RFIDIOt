#!/usr/bin/python

#  fdxbnum.py - generate / decode FDX-B EM4x05 compliant IDs
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
import string

try:
	card= rfidiot.card
except:
	os._exit(True)

args= rfidiot.args
help= rfidiot.help

card.info('fdxbnum v0.1f')

precoded= False

if not help and (len(args) == 1 or len(args) == 2):
	print "Decode: "
	if len(args[0]) == 16:
        	card.FDXBIDPrint(args[0])
	else:
		card.FDXBIDPrint(args[0][1:])
	if len(args) == 2:
		if args[1] == 'WRITE':
			precoded= True
		else:
			print 'Unrecognised option: ' + args[1]
			os._exit(True)
	else:
		os._exit(False)

if not help and (len(args) >= 3 or precoded):
	if precoded:
		id= args[0]
	else:
		print "Encode: ",
		id= card.FDXBIDEncode(args[0],args[1],args[2])
		print id
	out= card.FDXBID128Bit(id)
	print 'binary is',out
	if (len(args) == 4 and args[3] == 'WRITE') or precoded:
       		while True:
			# Q5 must be forced into Q5 mode to be sure of detection so try that first 
			if card.readertype == card.READER_ACG:
				card.settagtype(card.Q5)
			card.select()
			if card.readertype == card.READER_ACG:
				if not card.tagtype == card.Q5:
					card.settagtype(card.ALL)
               		card.waitfortag('Waiting for blank tag...')
               		print '  Tag ID: ' + card.data
			if card.tagtype == card.Q5 or card.tagtype == card.HITAG2:
               			x= string.upper(raw_input('  *** Warning! This will overwrite TAG! Proceed (y/n)? '))
               			if x == 'N':
                       			os._exit(False)
               			if x == 'Y':
                       			break
			else:
				x= raw_input('  Incompatible TAG! Hit <RETURN> to retry...')
		writetag= True
		print
	else:
		writetag= False
	# now turn it all back to 4 byte hex blocks for writing
	outbin= ''
	outhex= ['','','','','']
	# control block for Q5:
	# carrier 32 (2 * 15 + 2)
	# rf/? (don't care) - set to 00
	# data inverted
	# biphase
	# maxblock 4
	print '  Q5 Control Block:  ',
	q5control= '6000F0E8'
	print q5control
	for x in range(0,len(out),8):
		outbin += chr(int(out[x:x + 8],2))
	for x in range(0,len(outbin),4):
		print '    Q5 Data Block %02d:' % (x / 4 + 1),
		outhex[x / 4 + 1]= card.ToHex(outbin[x:x+4])
		print outhex[x / 4 + 1]
	# control block for Hitag2
	# Public Mode B
	# default password
	print
	print '  Hitag2 Control Block:  ',
	h2control= card.HITAG2_PUBLIC_B + card.HITAG2_TRANSPORT_TAG
	print h2control
	for x in range(1,5,1):
		print '    Hitag2 Data Block %02d:' % (x + 3),
		print outhex[x]
	if writetag == True:
		print 
		print '  Writing to tag type: ' + card.LFXTags[card.tagtype]
		if card.tagtype == card.Q5:
			outhex[0]= q5control
			offset= 0
		if card.tagtype == card.HITAG2:
			outhex[0]= h2control
			offset= 3
			if card.readertype == card.READER_ACG:	
				card.login('','',card.HITAG2_TRANSPORT_RWD)
		for x in range(4 + offset,-1 + offset,-1):
			print "    Writing block %02x:" % x,
        		if not card.writeblock(x,outhex[x - offset]):
				# we expect a Q5 to fail after writing the control block as it re-reads
				# it before trying to verify the write and switches mode so is now no longer in Q5 mode
				if x == offset:
					print '    Control:  ' + outhex[x - offset]
					print
					print '  Done!'
					# now check for FDX-B ID
               				card.settagtype(card.EM4x05)
					card.select()
					print '  Card ID: ' + card.data
				else:
                			print 'Write failed!'
					if card.readertype == card.READER_FROSCH:
						print card.FROSCH_Errors[card.errorcode]
                			os._exit(True)
			else:
				# hitag2 don't change mode until the next time they're selected so write
				# confirmation of control block should be ok
				if x == offset:
					print '    Control:  ' + outhex[x - offset]
					print
					print '  Done!'
					# now check for FDX-B ID
					card.reset()
               				card.settagtype(card.EM4x05)
					card.select()
					print '  Card ID: ' + card.data
				else:
					print outhex[x - offset]
		if card.readertype == card.READER_ACG:	
               		card.settagtype(card.ALL)
	os._exit(False)
print sys.argv[0] + ' - generate / decode FDX-B EM4x05 compliant IDs'
print 'Usage: ' + sys.argv[0] + ' [OPTIONS] <ID> [WRITE] | <APPID> <COUNTRY CODE> <NATIONAL ID> [WRITE]'
print
print '\tIf a single 16 HEX digit ID is provided, it will be decoded according to the FDX-B standard.'
print '\tAlternatively, specifying a 4 HEX digit Application ID, 3 or 4 digit decimal country code'
print '\t(normally based on ISO-3166 country codes or ICAR.ORG manufacturer codes, range 0 - 4095)'
print '\tand a decimal National ID Number will generate a 16 HEX digit ID.'
print '\tNote: Application ID 8000 is \'Animal\', and 0000 is non-Animal.'
print '\tMaximum value for country code is 999 according to the standard, but 4 digits will work.'
print '\tMaximum value for National ID is 274877906943.'
print
print '\tIf the WRITE option is specified, a Q5 or Hitag2 will be programmed to emulate FDX-B.'
print
os._exit(True)
