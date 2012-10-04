#!/usr/bin/python

#  hitag2reset.py - hitag2 tags need love too...
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
	print "Couldn't open reader!"
        os._exit(True)

args= rfidiot.args
help= rfidiot.help

card.info('hitag2reset v0.1e')

# standard config block
#CFB='06' + card.HITAG2_TRANSPORT_TAG
CFB=card.HITAG2_PASSWORD + card.HITAG2_TRANSPORT_TAG
BLK1= card.HITAG2_TRANSPORT_RWD

if len(args) == 0 or len(args) > 2 or help:
	print sys.argv[0] + ' - return a Hitag2 tag to life'
	print 'Usage: ' + sys.argv[0] + ' <CONTROL> [<OLD PASSWD> <NEW PASSWD>]'
	print
	print 'If the optional PASSWD fields are specified, the password will be set,'
	print 'otherwise factory password \'%s\' will be used' % card.HITAG2_TRANSPORT_RWD
	os._exit(True)

if args[0] == 'CONTROL':
       	while True:
               	print
#		if card.frosch(card.FR_HT2_Read_PublicB):
#              		print '  Card ID: ' + card.data
               	x= string.upper(raw_input('  *** Warning! This will overwrite TAG! Place card and proceed (y/n)? '))
               	if x == 'N':
               		os._exit(False)
       		if x == 'Y':
			break
	print 'Writing...'
	logins= 0
	if (card.h2publicselect()):
		print 'Hitag2 ID: ' + card.data
	else:
		print 'No TAG, or incompatible hardware!'
		os._exit(True)
	if not card.writeblock(3,CFB):
		print card.FROSCH_Errors[card.errorcode]
		print 'Block 3 write failed!'
		os._exit(True)
	else:
		# set new passord if specified
		if len(args) > 1:
			BLK1= args[1]
		#if not card.writeblock(1,B1) or not card.writeblock(2,B2):
		if not card.writeblock(1,BLK1):
			print 'Block 1 write failed!'
			print card.FROSCH_Errors[card.errorcode]
			os._exit(True)	 	
	card.settagtype(card.ALL)
	print 'Done!'
       	if card.select():
       		print '  Card ID: ' + card.uid
os._exit(False)
