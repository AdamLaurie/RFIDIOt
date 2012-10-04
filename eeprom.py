#!/usr/bin/python

#  eeprom.py - display reader's eeprom settings
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

card.info('eeprom v0.1e')
print 'Station:\t' + card.station()
print 'Protocol:\t' + card.PCON()
print 'Protocol2:\t' + card.PCON2()
print 'Protocol3:\t' + card.PCON3()

address= 0
while address < 0xf0:
	print 'address %02x:\t%s' % (address,card.readEEPROM(address))
	address += 1
