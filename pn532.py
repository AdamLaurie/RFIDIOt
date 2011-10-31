#!/usr/bin/python

#  pn532.py - NXP PN532 definitions for restricted functions
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


PN532_APDU=		{
			'GET_GENERAL_STATUS' : ['d4','04'],
			'GET_PN532_FIRMWARE' : ['d4','02'],
			'IN_ATR' : ['d4','50'],
			'IN_AUTO_POLL' : ['d4','60'],
			'IN_COMMUNICATE_THRU' : ['d4','42'],
			'IN_DATA_EXCHANGE' : ['d4','40'],
			'IN_LIST_PASSIVE_TARGET' : ['d4','4a'],
			'IN_SELECT' : ['d4','54'],
			'TG_GET_DATA' : ['d4','86'],
			'TG_INIT_AS_TARGET' : ['d4','8c'],
			'TG_SET_DATA' : ['d4','8e'],
			}

PN532_FUNCTIONS=	{
			0x01 : 'ISO/IEC 14443 Type A',
			0x02 : 'ISO/IEC 14443 Type B',
			0x04 : 'ISO/IEC 18092',
			}

PN532_OK= 'D503'

PN532_BAUDRATES= 	{
			0x00 : '106 kbps',
			0x01 : '212 kbps',
			0x02 : '424 kbps',
			0x10 : '212 kbps',
			0x20 : '424 kbps',
			}

PN532_FRAMING= 		{
			0x00 : 'Mifare',
			0x01 : 'Active mode',
			0x02 : 'FeliCa',
			}

PN532_TARGETS=		{
			'00' : 'Generic passive 106kbps (ISO/IEC1443-4A,mifare,DEP)',
			'10' : 'mifare card',
			}

PN532_MODULATION=	{
			0x00 : 'Mifare, ISO/IEC 14443-3 Type A/B, ISO/IEC 18092 passive 106 kbps',
			0x01 : 'ISO/IEC 18092 active',
			0x02 : 'Innovision Jewel',
			0x10 : 'FeliCa, ISO/IEC 18092 passive 212/424 kbps',
			}

PN532_ERRORS=		{
			0x00 : 'No Error',
			0x01 : 'Time Out',
			0x02 : 'CRC Error',
			0x03 : 'Parity Error',
			0x04 : 'Erroneous Bit Count during Aticollision/Select (ISO 14443-3/ISO 18092 106kbps)',
			0x05 : 'Mifare Framing Error',
			0x06 : 'Abnormal Bit Collision during Bitwise Anticollision (106 kbps)',
			0x07 : 'Communication Buffer Size Insufficient',
			0x09 : 'RF Buffer Overflow (Register CIU_ERROR BufferOvfl)',
			0x0a : 'Active Communication RF Timeout',
			0x0b : 'RF Protocol Error',
			0x0d : 'Antenna Overheat',
			0x0e : 'Internal Buffer Overflow',
			0x10 : 'Invalid Parameter',
			0x12 : 'DEP protocol - initiator command not supported',
			0x13 : 'DEP protocol - data format out of spec',
			0x14 : 'Mifare authentication error',
			0x23 : 'ISO/IEC 14443-3 UID check byte wrong',
			0x25 : 'DEP protocol - invalid device state',
			0x26 : 'Operation not allowed in this configuration',
			0x27 : 'Command out of context',
			0x29 : 'Target released by Initiator',
			0x2a : 'ID mismatch - card has been exchanged',
			0x2b : 'Activated card missing',
			0x2c : 'NFCID3 mismatch',
			0x2d : 'Over-current event detected',
			0x2e : 'NAD missing in DEP frame',
			}

PN532_RF=	{
		0x00 : 'Not present',
		0x01 : 'Present',
		}

# pn532 functions

# print pn532 firmware details
def pn532_print_firmware(data):
	if not data[:4] == PN532_OK:
		print '  Bad data from PN532:', data
	else:
		print '       IC:', data[4:6]
		print '      Rev: %d.%d' %  (int(data[6:8],16),int(data[8:10]))
		print '  Support:',
		support= int(data[10:12],16)
		spacing= ''
		for n in PN532_FUNCTIONS.keys():
			if support & n:
				print spacing + PN532_FUNCTIONS[n]
				spacing= '           '
		print

# print pn532 antenna status and return number of tags in field
def pn532_print_status(data):
	print '  Reader PN532 Status:'
	print '      Last error:', PN532_ERRORS[int(data[4:6])]
	print '     External RF:', PN532_RF[int(data[6:8],16)]
	tags= int(data[8:10],16)
	print '    TAGS present:', tags
	for n in range(tags):
		print '    Tag number %d:' % (n + 1)
		print '      Logical number:', data[10 + n * 2:12 + n * 2]
		print '         RX Baudrate:', PN532_BAUDRATES[int(data[12 + n * 2:14 + n * 2],16)]
		print '         TX Baudrate:', PN532_BAUDRATES[int(data[14 + n * 2:16 + n * 2],16)]
		print '          Modulation:', PN532_MODULATION[int(data[16 + n * 2:18 + n * 2],16)]
		print '      SAM Status:', data[18 + n * 2:20 + n * 2]
	print
	return tags
