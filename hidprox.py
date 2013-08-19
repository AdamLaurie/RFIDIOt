#!/usr/bin/python


#  hidprox.py - show HID Prox card type and site/id code
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


import sys
import os
import string
import rfidiot

try:
        card= rfidiot.card
except:
	print "Couldn't open reader!"
        os._exit(True)

card.info('hidprox v0.1f')

if not card.readersubtype == card.READER_OMNIKEY:
	print 'Reader type not supported!', card.ReaderSubType, card.READER_OMNIKEY
	os._exit(True)

try:
	card.select()
	prox= card.pcsc_atr[:6]
	type= card.HID_PROX_TYPES[prox]
	print '  Card type:', type
except:
	if not card.pcsc_atr:
		print 'No card detected!'
	else:
		print 'Unrecognised card type! ATR:', card.pcsc_atr
	os._exit(True)

# H10301 - 26 bit (FAC + CN)
if prox == card.HID_PROX_H10301:
	fc= card.pcsc_atr[7:10]
	cn= card.pcsc_atr[11:16]
	octal= '%o' % int(card.pcsc_atr[7:16])

# H10301 - 26 bit (FAC + CN) (ATR in HEX)
if prox == card.HID_PROX_H10301_H:
	binary= card.ToBinaryString(card.pcsc_atr[6:].decode('hex'))
	# strip leading zeros and parity
	binary= binary[7:]
	binary= binary[:-1]
	fc= int(binary[:8],2)
	cn= int(binary[8:],2)
	octal= '%o' % int(card.pcsc_atr[6:],16)

# H10302 - 37 bit (CN)
if prox == card.HID_PROX_H10302:
	fc= 'n/a'
	cn= card.pcsc_atr[6:18]
	octal= '%o' % int(card.pcsc_atr[6:18])

# H10302 - 37 bit (CN) (ATR in HEX)
if prox == card.HID_PROX_H10302_H:
	fc= 'n/a'
	binary= card.ToBinaryString(card.pcsc_atr[6:].decode('hex'))
	# strip leading zeros and parity
	binary= binary[8:]
	binary= binary[:-1]
	cn= int(binary,2)
	octal= '%o' % int(card.pcsc_atr[6:],16)

# H10304 - 37 bit (FAC + CN)
if prox == card.HID_PROX_H10304:
	fc= card.pcsc_atr[7:12]
	cn= card.pcsc_atr[12:18]
	octal= '%o' % int(card.pcsc_atr[7:18])

# H10320 - 32 bit clock/data card
if prox == card.HID_PROX_H10320:
	fc= 'n/a'
	cn= card.pcsc_atr[6:14]
	octal= '%o' % int(card.pcsc_atr[6:14])

# Corp 1000 - 35 bit (CIC + CN)	
if prox == card.HID_PROX_CORP1K:
	fc= card.pcsc_atr[6:10]
	cn= card.pcsc_atr[10:18]
	octal= '%o' % int(card.pcsc_atr[6:18])

print
print '    Facility Code:', fc
print '      Card Number:', cn
print '            Octal:', octal
print
os._exit(False)
