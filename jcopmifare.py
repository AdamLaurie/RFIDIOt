#!/usr/bin/python


#  jcopmifare.py - test program for mifare emulation on JCOP
#  
#  This program can be used to test READ/WRITE functionality of the built-in
#  mifare emulation on mifare enabled JCOP cards.
#  The mifare access applet jcop_mifare_access.cap must be loaded onto the card first.
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
# history
#	15/11/08 - ver 0.1a - first cut, seems to work. :)
#	13/01/09 - ver 0.1b - add RANDOM UID mode

import rfidiot
import sys
import os

try:
        card= rfidiot.card
except:
	print "Couldn't open reader!"
        os._exit(True)

args= rfidiot.args
Help= rfidiot.help

# fixed values required by JCOP applet
CLA= '00'
INS= 'MIFARE_ACCESS'
P1= '03'
WRITE= '01'
READ= '02'
RANDOM= '03'
MIFARE_AID= 'DC4420060606'

card.info('jcopmifare v0.1e')

if Help or len(args) < 2:
	print '\nUsage:\n\n\t%s [OPTIONS] <READ|WRITE|RANDOM> <MIFARE_PWD> [SECTOR] [HEX DATA]' % sys.argv[0]
	print
	print '\tMIFARE_PWD should be the HEX 8 BYTE MifarePWD produced by mifarekeys.py, or the'
	print '\tRANDOM_UID secret key.'
	print
	print '\tSECTOR number must be specified for READ and WRITE operations. Note that not all'
	print '\tsectors are WRITEable.'
	print
	print '\tRANDOM will set card into RANDOM_UID mode. All future selects will return a random'
	print '\tUID instead of the one stored in sector 0. This behaviour cannot be reversed.'
	print
	print '\tHEX DATA must be 16 BYTES worth of HEX for WRITE operations.' 
	print
	print '\t(default NXP transport keys are both FFFFFFFFFFFF, so MifarePWD is 0B54570745FE3AE7)'
	print '\t(sector 0 default is A0A1A2A3A4A5, so MifarePWD is 0FB3BBC7099ED432)'
	print
	print '\tExample:'
	print
	print '\t\t./jcopmifare.py WRITE 0B54570745FE3AE7 1 12345678123456781234567812345678'
	print
	print
	print '\tNote that jcop_mifare_access.cap or native Mifare emulation must be active on the card.'
	print
	os._exit(True)

def mifare_read(key,sector):
	cla= CLA
	ins= INS
	p1= P1
	p2= READ
	data= key + '%02X' % int(sector)
	lc= '%02X' % (len(data) / 2)
	le= '10'

	if card.send_apdu('','','','',cla,ins,p1,p2,lc,data,le):
		return True, card.data
	return False, card.errorcode

def mifare_write(key,sector,sectordata):
	cla= CLA
	ins= INS
	p1= P1
	p2= WRITE
	data= key + sectordata + '%02X' % int(sector)
	lc= '%02X' % (len(data) / 2)
	
	if card.send_apdu('','','','',cla,ins,p1,p2,lc,data,''):
		return True, card.data
	return False, card.errorcode

def mifare_random(key):
	cla= CLA
	ins= INS
	p1= P1
	p2= RANDOM
	data= key
	lc= '%02X' % (len(data) / 2)
	
	if card.send_apdu('','','','',cla,ins,p1,p2,lc,data,''):
		return True, card.data
	return False, card.errorcode

def select_mifare_app():
        "select mifare application (AID: DC4420060606)"
        ins= 'SELECT_FILE'
        p1= '04'
        p2= '0C'
        data= MIFARE_AID
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

if card.select():
	print '    Card ID: ' + card.uid
	if card.readertype == card.READER_PCSC:
		print '    ATR: ' + card.pcsc_atr
else:
	print '    No card present'

# high speed select required for ACG
if not card.hsselect('08'):
        print '    Could not select card for APDU processing'
        os._exit(True)

if not select_mifare_app():
	print '  Could not select mifare applet!'
	os._exit(True)

if args[0] == 'READ':
	stat, data= mifare_read(args[1],args[2])
	if not stat:
		error_exit('Read failed', data)
	else:
		print 'Data: ', data
		os._exit(False)

if args[0] == 'WRITE':
	stat, data= mifare_write(args[1],args[2],args[3])
	if not stat:
		error_exit('Write failed', data)
	else:
		print 'Write completed'
		os._exit(False)

if args[0] == 'RANDOM':
	stat, data= mifare_random(args[1])
	if not stat:
		error_exit('Random_UID mode failed', data)
	else:
		print 'Random_UID set'
		os._exit(False)



print "Unrecognised command:", args[0]
os._exit(True)
