#!/usr/bin/python

#  demotag.py - test IAIK TUG DemoTag`
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
        os._exit(False)

args= rfidiot.args

print 'Setting ID to: ' + args[0]
print card.demotag(card.DT_SET_UID,card.ToBinary(args[0]))
