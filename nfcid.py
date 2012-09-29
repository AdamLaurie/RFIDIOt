#!/usr/bin/python

#
# NFC ID.py - Python code for Identifying NFC cards
# version 0.1
# Nick von Dadelszen (nick@lateralsecurity.com)
# Lateral Security (www.lateralsecurity.com)

#
# This code is copyright (c) Lateral Security, 2011, All rights reserved.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

#import RFIDIOtconfig
import sys
import os
import pyandroid
import datetime

Verbose= True
Quiet= True

aidlist= 	[
		['MASTERCARD',		'a0000000041010'],
		['MASTERCARD',		'a0000000049999'],
		['VISA',		'a000000003'],
		['VISA Debit/Credit',	'a0000000031010'],
		['VISA Credit',		'a000000003101001'],
		['VISA Debit',		'a000000003101002'],
		['VISA Electron',	'a0000000032010'],
		['VISA V Pay',		'a0000000032020'],
		['VISA Interlink',	'a0000000033010'],
		['VISA Plus',		'a0000000038010'],
		['VISA ATM',		'a000000003999910'],
		['Maestro',		'a0000000043060'],
		['Maestro UK',		'a0000000050001'],
		['Maestro TEST',	'b012345678'],
		['Self Service',	'a00000002401'],
		['American Express',	'a000000025'],
		['ExpressPay',		'a000000025010701'],
		['Link',		'a0000000291010'],
	    ['Alias AID',		'a0000000291010'],
		['Cirrus',		'a0000000046000'],
		['Snapper Card',		'D4100000030001'],		
		['Passport',		'A0000002471001'],		
	    	]


n = pyandroid.Android()

while(42):
	uid = n.select()
	print 'GMT Timestamp: ' + str(datetime.datetime.now())

	if not Quiet:
		print '\nID: ' + uid
		print '  Data:'

	current = 0
	cc_data = False

	while current < len(aidlist):
		if Verbose:
			print 'Trying AID: '+ aidlist[current][0]  + ':' + aidlist[current][1]
		apdu = '00A4040007' + aidlist[current][1]
		r = n.sendAPDU(apdu)
		#print r
		#print r[-4:]	
		if not r[-4:] == '9000':
			apdu = apdu + '00'
			r = n.sendAPDU(apdu)
			#print r
			#print r[-4:]

		if r[-4:] == '9000':
			#print card.data + card.errorcode
			uid = uid[:-1]
			n.sendResults("Card found-UID: " + uid + "-Card type: " + aidlist[current][0])
			break
			
		current += 1	

	if not Quiet:			
		print 'Ending now ...'
	n.deconfigure()
	print 

