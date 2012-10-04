#!/usr/bin/python


#  jcopsetatrhist.py - set ATR History bytes on JCOP cards
#  
#  The applet jcop_set_atr_hist.cap must be loaded onto the card first,
#  and it must be installed as "default selectable" (priv mode 0x04).
# 
#  Adam Laurie <adam@algroup.co.uk>
#  http://rfidiot.org/
# 
#  This code is copyright (c) Adam Laurie, 2008, All rights reserved.
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
Help= rfidiot.help

# fixed values required by JCOP applet
CLA= '80'
P1= '00'
P2= '00'
JCOP_ATR_AID= 'DC4420060607'

if Help or len(args) < 2:
	print '\nUsage:\n\n\t%s [OPTIONS] \'SET\' <HEX DATA>' % sys.argv[0]
	print
	print '\tHEX DATA is up to 15 BYTES of ASCII HEX.' 
	print
	print '\tExample:'
	print
	print '\t./jcopsetatrhist.py SET 0064041101013180009000'
	print
	os._exit(True)

def jcop_set_atr_hist(bytes):
	cla= CLA
	ins= 'ATR_HIST'
	p1= P1
	p2= P2
	data= '%02X' % (len(bytes) / 2) + bytes
	lc= '%02X' % (len(data) / 2)
	if card.send_apdu('','','','',cla,ins,p1,p2,lc,data,''):
		return True, card.data
	return False, card.errorcode

def select_atrhist_app():
        "select atr_hist application (AID: DC4420060607)"
        ins= 'SELECT_FILE'
        p1= '04'
        p2= '0C'
        data= JCOP_ATR_AID
	lc= '%02X' % (len(data) / 2)
        card.send_apdu('','','','','',ins,p1,p2,lc,data,'')
        if card.errorcode == card.ISO_OK:
                return True
        else:
                return False

def error_exit(message,error):
	print '  %s, error number: %s' % (message,error),
	try:
		print card.ISO7816ErrorCodes[error]
	except:
		print
	os._exit(True)

card.info('jcopsetatrhist v0.1c')

if card.select():
	print '    Card ID: ' + card.uid
	if card.readertype == card.READER_PCSC:
		print '    ATR: ' + card.pcsc_atr
else:
	print '    No card present'
	os._exit(True)

# high speed select required for ACG
if not card.hsselect('08'):
        print '    Could not select card for APDU processing'
        os._exit(True)

if not select_atrhist_app():
	print
	print "  Can't select atrhist applet!"
	print '  Please load jcop_set_atr_hist.cap onto JCOP card.'
	print '  (Use command: gpshell java/jcop_set_atr_hist.gpsh)'
	print
	os._exit(True)
		
if args[0] == 'SET':
	stat, data= jcop_set_atr_hist(args[1])
	if not stat:
		error_exit('Set hist bytes failed', data)
	else:
		print
		print '  ATR History Bytes (ATS) set to', args[1]
		print 
		print '  *** Remove card from reader and replace to finalise!'
		print
		print '  You can now delete jcop_set_atr_hist.cap from the JCOP card.'
		print '  (Use command: gpshell java/jcop_delete_atr_hist.gpsh)'
		print
		os._exit(False)
else:
	print "Unrecognised command:", args[0]
	os._exit(True)
