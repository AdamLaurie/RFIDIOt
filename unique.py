#!/usr/bin/python

#  unique.py -  generate EM4x02 and/or UNIQUE compliant IDs
#       these can then be written to a Q5 tag to emulate EM4x02
#       by transmitting data blocks 1 & 2 (MAXBLOCK == 2),
#       or Hitag2 in Public Mode A with data stored in blocks
#       4 and 5.
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
import time

try:
	card= rfidiot.card
except:
	print "Couldn't open reader!"
	os._exit(True)

args= rfidiot.args
help= rfidiot.help

card.info('unique v0.1l')

# Q5 config block
Q5CFB='e601f004'
# Hitag2 config block
H2CFB= card.HITAG2_PUBLIC_A + card.HITAG2_TRANSPORT_TAG

if len(args) < 1 or len(args) > 3 or help:
    print
    print sys.argv[0] + ' - generate EM4x02 and/or UNIQUE compliant ID data blocks'
    print '\nUsage: ' + sys.argv[0] + ' [OPTIONS] <TYPE> <ID> [\"WRITE\"]'
    print '       ' + sys.argv[0] + ' [OPTIONS] <\"CLONE\">'
    print
    print '\t10 digit HEX ID will be translated to valid data for blocks 1 & 2'
    print '\tfor a Q5 tag running in EM4x02 emulation mode, and blocks 4 & 5 for'
    print '\ta Hitag2, where TYPE is U for UNIQUE code and E for EM4x02. For '
    print '\tguidance, standard emulation control blocks (0 & 3 respectively)'
    print '\twill also be displayed.' 
    print 
    print '\tIf the optional WRITE argument is specified, programming a Q5 or'
    print '\tHitag2 tag will be initiated.'
    print
    print '\tIf the single word CLONE is specified, the reader will scan for'
    print '\ta Unique tag and then wait for a suitable blank to be presented'
    print '\tfor writing. No prompting will take place before the target is'
    print '\toverwritten.'
    os._exit(True)


if len(args) == 1 and string.upper(args[0]) == "CLONE":
	type= 'UNIQUE'
	clone= True
	card.settagtype(card.EM4x02)
	card.waitfortag('Waiting for Unique tag...')
	id= card.uid
	idbin= card.UniqueToEM(card.HexReverse(id))
else:
	clone= False
	if len(args[1]) != 10:
		print 'ID must be 10 HEX digits!'
		os._exit(True)
	id= args[1]

if args[0] == 'E':
    type= 'EM4x02'
    idbin= card.UniqueToEM(card.HexReverse(id))
else:
    if args[0] == 'U':
        type= 'UNIQUE'
        idbin= card.ToBinaryString(card.ToBinary(id))
    else:
	if not clone:
        	print 'Unknown TYPE: ' + args[0]
        	os._exit(True)


out= card.Unique64Bit(idbin)
manchester= card.BinaryToManchester(out)
db1= '%08x' % int(out[:32],2)
db2= '%08x' % int(out[32:64],2)
print
print '  ' + type + ' ID: ' + id
print '  Q5 ID: ' + '%08x' % int(idbin[:32],2)
if type ==  'EM4x02':
    print '  UNIQUE ID: ' + '%10x' % int(idbin,2)
else:
    print '  EM4x02 ID: ' + ('%10x' % int(card.UniqueToEM(id),2))[::-1]
print '  Binary traceablility data: ' + out
print '  Manchester Encoded:        ' + manchester
print
print '  Q5 Config Block (0): ' + Q5CFB
print '  Data Block 1: ' + db1
print '  Data Block 2: ' + db2
print
print '  Hitag2 Config Block (3): ' + H2CFB 
print '  Data Block 4: ' + db1
print '  Data Block 5: ' + db2

if (len(args) == 3 and string.upper(args[2]) == 'WRITE') or clone:
	# check for Q5 first`
	if card.readertype == card.READER_ACG:
		card.settagtype(card.Q5)
		if not card.select():
                	card.settagtype(card.ALL)
        while not (card.tagtype == card.Q5 or card.tagtype == card.HITAG2):
        	card.waitfortag('Waiting for blank tag (Q5 or Hitag2)...')
        	print 'Tag ID: ' + card.uid
	if not clone:
      		x= string.upper(raw_input('  *** Warning! This will overwrite TAG! Proceed (y/n)? '))
       		if x != 'Y':
        	       	os._exit(False)
	# allow blank to settle
	time.sleep(2)
	print 'Writing...'
	if card.tagtype == card.Q5:
        	if not card.writeblock(0,Q5CFB) or not card.writeblock(1,db1) or not card.writeblock(2,db2):
            		print 'Write failed!'
            		os._exit(True)
	if card.tagtype == card.HITAG2:
        	if card.readertype == card.READER_ACG:
            		card.login('','',card.HITAG2_TRANSPORT_RWD)
        	if not card.writeblock(3,H2CFB) or not card.writeblock(4,db1) or not card.writeblock(5,db2):
            		print 'Write failed!'
            		os._exit(True)
	card.settagtype(card.EM4x02)
	card.select()
	print 'Card ID: ' + card.uid
	print '  Unique ID: ' + card.EMToUnique(card.uid)
	print 'Done!'
	card.settagtype(card.ALL)
os._exit(False)
