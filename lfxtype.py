#!/usr/bin/python


#  lfxtype.py - select card and display tag type
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


card.info('lfxtype v0.1j')
card.select()
ID= card.uid
if ID:
	print 'Card ID: ' + ID
	print 'Tag type: ' + card.LFXTags[card.tagtype]
	if card.tagtype == card.EM4x02:
		print '  Unique ID: ' + card.EMToUnique(ID)
		card.settagtype(card.Q5)
		card.select()
		if card.uid:
			print '  *** This is a Q5 tag in EM4x02 emulation mode ***'
	os._exit(False)
else:
	print 'No TAG present!'
	os._exit(True)
