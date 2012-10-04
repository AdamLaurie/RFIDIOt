#!/usr/bin/python

#  pn532emulate.py - switch NXP PN532 reader chip into TAG emulation mode
# 
#  Adam Laurie <adam@algroup.co.uk>
#  http://rfidiot.org/
# 
#  This code is copyright (c) Adam Laurie, 2009, All rights reserved.
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
from rfidiot.pn532 import *
import sys
import os

try:
        card= rfidiot.card
except:
        os._exit(True)

args= rfidiot.args
help= rfidiot.help

card.info('pn532emulate v0.1d')

if help or len(args) < 6: 
	print sys.argv[0] + ' - Switch NXP PN532 chip into emulation mode'
	print
	print 'Usage: ' + sys.argv[0] + ' <MODE> <SENS_RES> <NFCID1t> <SEL_RES> <NFCID2t> <PAD> <SYSTEM_CODE> <NFCID3t> [General Bytes] [Historical Bytes]'
	print
	print '  The NXP PN532 chip inside some readers (such as ACS/Tikitag) are capable of emulating the following tags:'
	print
	print '    ISO-14443-3'
	print '    ISO-14443-4'
	print '    Mifare'
	print '    FeliCa'
	print
	print '  Arguments should be specified as follows:'
	print
	print '    MODE (BitField, last 3 bits only):'
	print '        -----000 - Any'
	print '        -----001 - Passive only'
	print '        -----010 - DEP only'
	print '        -----100 - PICC only'
	print
	print '    SENS_RES:'
	print '        2 Bytes, LSB first, as defined in ISO 14443-3.'
	print
	print '    NFCID1t:'
	print "        UID Last 6 HEX digits ('08' will be prepended)."
	print
	print '    SEL_RES:'
	print '        1 Byte, as defined in ISO14443-4.'
	print
	print '    NFCID2t:'
	print "        8 Bytes target NFC ID2. Must start with '01fe'."
	print
	print '    PAD:'
	print '        8 Bytes.'
	print
	print '    SYSTEM_CODE:'
	print '        2 Bytes, returned in the POL_RES frame if the 4th byte of the incoming POL_REQ'
	print '        command frame is 0x01.'
	print 
	print '    NFCID3t:'
	print '        10 Bytes, used in the ATR_RES in case of ATR_REQ received from the initiator.'
	print
	print '    General Bytes:'
	print '        Optional, Max 47 Bytes, to be used in the ATR_RES.'
	print
	print '    Historical Bytes:'
	print '        Optional, Max 48 Bytes, to be used in the ATS when in ISO/IEC 14443-4 PICC'
	print '        emulation mode.'
	print 
	print '  Example:'
	print
	print '    ' + sys.argv[0] + ' 00 0800 dc4420 60 01fea2a3a4a5a6a7c0c1c2c3c4c5c6c7ffff aa998877665544332211 00 52464944494f7420504e353332'
	print
	print '    In ISO/IEC 14443-4 PICC emulation mode, the emulator will wait for initiator, then wait for an APDU,'
	print "    to which it will reply '9000' and exit."
	print
	os._exit(True)

if not card.readersubtype == card.READER_ACS:
	print '  Reader type not supported!'
	os._exit(True)

# switch off auto-polling (for ACS v1 firmware only) (doesn't seem to help anyway!)
#if not card.acs_send_apdu(card.PCSC_APDU['ACS_DISABLE_AUTO_POLL']):
#	print '  Could not disable auto-polling'
#	os._exit(True)

if card.acs_send_apdu(PN532_APDU['GET_PN532_FIRMWARE']):
        print '  NXP PN532 Firmware:'
	pn532_print_firmware(card.data)

if card.acs_send_apdu(PN532_APDU['GET_GENERAL_STATUS']):
	pn532_print_status(card.data)

mode= [args[0]]
sens_res= [args[1]]
uid= [args[2]]
sel_res= [args[3]]
felica= [args[4]]
nfcid=  [args[5]]
try:
	lengt= ['%02x' % (len(args[6]) / 2)]
	gt= [args[6]]
except:
	lengt= ['00']
	gt= ['']
try:
	lentk= ['%02x' % (len(args[7]) / 2)]
	tk= [args[7]]
except:
	lentk= ['00']
	tk= ['']

print '  Waiting for activation...'
card.acs_send_apdu(card.PCSC_APDU['ACS_LED_RED'])
status= card.acs_send_apdu(PN532_APDU['TG_INIT_AS_TARGET']+mode+sens_res+uid+sel_res+felica+nfcid+lengt+gt+lentk+tk)
if not status or not card.data[:4] == 'D58D':
		print 'Target Init failed:', card.errorcode
		os._exit(True)
mode= int(card.data[4:6],16)
baudrate= mode & 0x70
print '  Emulator activated:'
print '         UID: 08%s' % uid[0]
print '    Baudrate:', PN532_BAUDRATES[baudrate]
print '        Mode:',
if mode & 0x08:
	print 'ISO/IEC 14443-4 PICC'
if mode & 0x04:
	print 'DEP'
framing= mode & 0x03
print '     Framing:', PN532_FRAMING[framing]
print '   Initiator:', card.data[6:]
print

print '  Waiting for APDU...'
status= card.acs_send_apdu(PN532_APDU['TG_GET_DATA'])
if not status or not card.data[:4] == 'D587':
		print 'Target Get Data failed:', card.errorcode
		print 'Data:',card.data
		os._exit(True)
errorcode= int(card.data[4:6],16)
if not errorcode == 0x00:
	print 'Error:',PN532_ERRORS[errorcode]
	os._exit(True)
print '<<', card.data[6:]

print '>>', card.ISO_OK
status= card.acs_send_apdu(PN532_APDU['TG_SET_DATA']+[card.ISO_OK])
if not status:
	os._exit(True)
else:
	os._exit(False)
