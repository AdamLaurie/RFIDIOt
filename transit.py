#!/usr/bin/python

#  transit.py - generate / decode FDI Matalec Transit 500 and Transit 999 UIDs
# 
#  Adam Laurie <adam@algroup.co.uk>
#  http://rfidiot.org/
# 
#  This code is copyright (c) Adam Laurie, 2009, All rights reserved.
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
	print "Couldn't open reader!"
	os._exit(True)

args= rfidiot.args
help= rfidiot.help

card.info('transit v0.1b')

precoded= False

if not help and len(args) > 0 and len(args[0]) == 64:
	print "\nDecode: ",
       	card.TRANSITIDPrint(args[0])
	if len(args) == 2:
		if args[1] == 'WRITE':
			precoded= True
		else:
			print 'Unrecognised option: ' + args[1]
			os._exit(True)
	else:
		print
		os._exit(False)

if not help and ((len(args) > 0 and len(args[0]) == 8) or precoded):
	if precoded:
		out= args[0]
	else:
		print "\nEncode: ",
		out= card.TRANSITIDEncode(args[0])
	print out
	if (len(args) == 2 and args[1] == 'WRITE') or precoded:
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
			if card.tagtype == card.Q5:
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
	# data not inverted
	# manchester
	# maxblock 2
	print '  Q5 Control Block:  ',
	q5control= '6000F004'
	print q5control
	for x in range(0,len(out),8):
		outbin += chr(int(out[x:x + 8],2))
	for x in range(0,len(outbin),4):
		print '    Q5 Data Block %02d:' % (x / 4 + 1),
		outhex[x / 4 + 1]= card.ToHex(outbin[x:x+4])
		print outhex[x / 4 + 1]
	if writetag == True:
		print 
		outhex[0]= q5control
		for x in range(2,-1,-1):
			if(x != 0):
				print "    Writing block %02x:" % x,
        		if not card.writeblock(x,outhex[x]):
				# we expect a Q5 to fail after writing the control block as it re-reads
				# it before trying to verify the write and switches mode so is now no longer in Q5 mode
				if x == 0:
					print '             Control: ' + outhex[x]
					print
					print '  Done!'
				else:
                			print 'Write failed!'
                			os._exit(True)
			else:
				print outhex[x]
		if card.readertype == card.READER_ACG:	
               		card.settagtype(card.ALL)
	print
	os._exit(False)
print
print sys.argv[0] + ' - Q5 encode / decode TRANSIT compliant IDs'
print '\nUsage: ' + sys.argv[0] + ' [OPTIONS] <UID> [WRITE]'
print
print '\tIf a single 64 Bit BINARY UID is provided, it will be decoded according to the TRANSIT standard.'
print '\tAlternatively, specifying a 8 HEX digit UID will encode the 64 Bit BINARY with LRC and sentinels.'
print
print '\tIf the WRITE option is specified, a Q5 will be programmed to emulate a TRANSIT tag.'
print
os._exit(True)
