#!/usr/bin/python

#  q5reset.py - plooking too hard on your Q5? this should sort it out.
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

card.info('q5reset v0.1g')

# standard config block
CFB='e601f004'
B1='ff801bc2'
B2='52500006'

if help or len(args) == 0 or len(args) > 2:
	print sys.argv[0] + ' - sooth and heal a sorely mistreated Q5 tag'
	print 'Usage: ' + sys.argv[0] + ' [OPTIONS] <CONTROL> [ID]'
	print
	print '\tIf the optional 8 HEX-digit ID argument is specified, the' 
	print '\tQ5 tag will be programmed to that ID. Otherwise, only the' 
	print '\tcontrol block will be written. If the literal \'ID\' is used'
	print '\tthen a default ID will be programmed.'
	print
	print '\tNote that not all Q5 chips allow programming of their ID!'
	print
	os._exit(True)

if args[0] == 'CONTROL':
       	card.settagtype(card.ALL)
       	while True:
               	print
               	card.select()
               	print '  Card ID: ' + card.uid
               	x= string.upper(raw_input('  *** Warning! This will overwrite TAG! Place defective card and proceed (y/n)? '))
               	if x == 'N':
               		os._exit(False)
       		if x == 'Y':
			break
	print 'Writing...'
       	card.settagtype(card.Q5)
	card.select()
	if not card.writeblock(0,CFB):
		print 'Write failed!'
		os._exit(True)
	else:
		if len(args) > 1:
			if not args[1] == 'ID':
				out= card.Unique64Bit(card.HexToQ5(args[1] + '00'))
				B1= '%08x' % int(out[:32],2)
				B2= '%08x' % int(out[32:64],2)
			if not card.writeblock(1,B1) or not card.writeblock(2,B2):
				print 'Write failed!'
				os._exit(True)	 	
	print 'Done!'
       	card.select()
       	print '  Card ID: ' + card.data
	card.settagtype(card.ALL)
os._exit(False)
