#!/usr/bin/python


#  cardselect.py - select card and display ID
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

args= rfidiot.args

card.info('cardselect v0.1m')
# force card type if specified
if len(args) == 1:
	card.settagtype(args[0])
else:
	card.settagtype(card.ALL)

if card.select():
	print '    Card ID: ' + card.uid
	if card.readertype == card.READER_PCSC:
		print '    ATR: ' + card.pcsc_atr
else:
	if card.errorcode:
		print '    '+card.ISO7816ErrorCodes[card.errorcode]
	else:
		print '    No card present'
		os._exit(True)
os._exit(False)
