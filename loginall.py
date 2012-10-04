#!/usr/bin/python

#  loginall.py - attempt to login to each sector with transport keys
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

try:
        card= rfidiot.card
except:
	print "Couldn't open reader!"
        os._exit(True)

card.info('loginall v0.1h')

card.select()
print '\ncard id: ' + card.uid

block = 0

while block < 16:
	for X in [ 'AA', 'BB', 'FF' ]:
		card.select()
		print '%02x %s: ' % (block, X),
		if card.login(block, X, ''):
			print "success!"
		elif card.errorcode:
			print "error: " + card.errorcode
		else:
			print "failed"
	block += 1
os._exit(False)
