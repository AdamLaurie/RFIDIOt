#! /usr/bin/env python
"""
Script that tries to select the EMV Payment Systems Directory on all inserted cards.

Copyright 2008 RFIDIOt
Author: Adam Laurie, mailto:adam@algroup.co.uk
	http://rfidiot.org/ChAP.py

This file is based on an example program from scard-python.
  Originally Copyright 2001-2007 gemalto
  Author: Jean-Daniel Aussel, mailto:jean-daniel.aussel@gemalto.com

scard-python is free software; you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation; either version 2.1 of the License, or
(at your option) any later version.

scard-python is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with scard-python; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""

from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnection import CardConnection
from smartcard.CardConnectionObserver import ConsoleCardConnectionObserver
from smartcard.Exceptions import CardRequestTimeoutException

import getopt
import sys
from operator import *

# local imports
from rfidiot.iso3166 import ISO3166CountryCodes

# default global options
BruteforcePrimitives= False
BruteforceFiles= False
BruteforceAID= False
BruteforceEMV= False
OutputFiles= False
Debug= False
Protocol= CardConnection.T0_protocol
RawOutput= False
Verbose= False

# Global VARs for data interchange
Cdol1= ''
Cdol2= ''
CurrentAID= ''

# known AIDs
# please mail new AIDs to aid@rfidiot.org
KNOWN_AIDS= 	[
		['VISA',0xa0,0x00,0x00,0x00,0x03],
		['VISA Debit/Credit',0xa0,0x00,0x00,0x00,0x03,0x10,0x10],
		['VISA Credit',0xa0,0x00,0x00,0x00,0x03,0x10,0x10,0x01],
		['VISA Debit',0xa0,0x00,0x00,0x00,0x03,0x10,0x10,0x02],
		['VISA Electron',0xa0,0x00,0x00,0x00,0x03,0x20,0x10],
		['VISA Interlink',0xa0,0x00,0x00,0x00,0x03,0x30,0x10],
		['VISA Plus',0xa0,0x00,0x00,0x00,0x03,0x80,0x10],
		['VISA ATM',0xa0,0x00,0x00,0x00,0x03,0x99,0x99,0x10],
		['MASTERCARD',0xa0,0x00,0x00,0x00,0x04,0x10,0x10],
		['Maestro',0xa0,0x00,0x00,0x00,0x04,0x30,0x60],
		['Maestro UK',0xa0,0x00,0x00,0x00,0x05,0x00,0x01],
		['Maestro TEST',0xb0,0x12,0x34,0x56,0x78],
		['Self Service',0xa0,0x00,0x00,0x00,0x24,0x01],
		['American Express',0xa0,0x00,0x00,0x00,0x25],
		['ExpressPay',0xa0,0x00,0x00,0x00,0x25,0x01,0x07,0x01],
		['Link',0xa0,0x00,0x00,0x00,0x29,0x10,0x10],
	     	['Alias AID',0xa0,0x00,0x00,0x00,0x29,0x10,0x10],
	    	]

# Master Data File for PSE
DF_PSE = [0x31, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31]

# define the apdus used in this script
AAC= 0
TC= 0x40
ARQC= 0x80
GENERATE_AC= [0x80,0xae]
GET_CHALLENGE= [0x00,0x84,0x00]
GET_DATA = [0x80, 0xca]
GET_PROCESSING_OPTIONS = [0x80,0xa8,0x00,0x00,0x02,0x83,0x00,0x00]
GET_RESPONSE = [0x00, 0xC0, 0x00, 0x00 ]
READ_RECORD = [0x00, 0xb2]
SELECT = [0x00, 0xA4, 0x04, 0x00]
UNBLOCK_PIN= [0x84,0x24,0x00,0x00,0x00]
VERIFY= [0x00,0x20,0x00,0x80]

#BRUTE_AID= [0xa0,0x00,0x00,0x00]
BRUTE_AID= []

# define tags for response
BINARY= 0
TEXT= 1
BER_TLV= 2
NUMERIC= 3
MIXED= 4
TEMPLATE= 0
ITEM= 1
VALUE= 2
SFI= 0x88
CDOL1= 0x8c
CDOL2= 0x8d
TAGS= 	{	
	0x4f:['Application Identifier (AID)',BINARY,ITEM],
	0x50:['Application Label',TEXT,ITEM],
	0x57:['Track 2 Equivalent Data',BINARY,ITEM],
	0x5a:['Application Primary Account Number (PAN)',NUMERIC,ITEM],
	0x6f:['File Control Information (FCI) Template',BINARY,TEMPLATE],
	0x70:['Record Template',BINARY,TEMPLATE],
	0x77:['Response Message Template Format 2',BINARY,ITEM],
	0x80:['Response Message Template Format 1',BINARY,ITEM],
	0x82:['Application Interchange Profile',BINARY,ITEM],
	0x83:['Command Template',BER_TLV,ITEM],
	0x84:['DF Name',MIXED,ITEM],
	0x86:['Issuer Script Command',BER_TLV,ITEM],
	0x87:['Application Priority Indicator',BER_TLV,ITEM],
	0x88:['Short File Identifier',BINARY,ITEM],
	0x8a:['Authorisation Response Code',BINARY,VALUE],
	0x8c:['Card Risk Management Data Object List 1 (CDOL1)',BINARY,TEMPLATE],
	0x8d:['Card Risk Management Data Object List 2 (CDOL2)',BINARY,TEMPLATE],
	0x8e:['Cardholder Verification Method (CVM) List',BINARY,ITEM],
	0x8f:['Certification Authority Public Key Index',BINARY,ITEM],
	0x93:['Signed Static Application Data',BINARY,ITEM],
	0x94:['Application File Locator',BINARY,ITEM],
	0x95:['Terminal Verification Results',BINARY,VALUE],
	0x97:['Transaction Certificate Data Object List (TDOL)',BER_TLV,ITEM],
	0x9c:['Transaction Type',BINARY,VALUE],
	0x9d:['Directory Definition File',BINARY,ITEM],
	0xa5:['Proprietary Information',BINARY,TEMPLATE],
	0x5f20:['Cardholder Name',TEXT,ITEM],
	0x5f24:['Application Expiration Date YYMMDD',NUMERIC,ITEM],
	0x5f25:['Application Effective Date YYMMDD',NUMERIC,ITEM],
	0x5f28:['Issuer Country Code',NUMERIC,ITEM],
	0x5f2a:['Transaction Currency Code',BINARY,VALUE],
	0x5f2d:['Language Preference',TEXT,ITEM],
	0x5f30:['Service Code',NUMERIC,ITEM],
	0x5f34:['Application Primary Account Number (PAN) Sequence Number',NUMERIC,ITEM],
	0x5f50:['Issuer URL',TEXT,ITEM],
	0x92:['Issuer Public Key Remainder',BINARY,ITEM],
	0x9a:['Transaction Date',BINARY,VALUE],
	0x9f02:['Amount, Authorised (Numeric)',BINARY,VALUE],
	0x9f03:['Amount, Other (Numeric)',BINARY,VALUE],
	0x9f04:['Amount, Other (Binary)',BINARY,VALUE],
	0x9f05:['Application Discretionary Data',BINARY,ITEM],
	0x9f07:['Application Usage Control',BINARY,ITEM],
	0x9f08:['Application Version Number',BINARY,ITEM],
	0x9f0d:['Issuer Action Code - Default',BINARY,ITEM],
	0x9f0e:['Issuer Action Code - Denial',BINARY,ITEM],
	0x9f0f:['Issuer Action Code - Online',BINARY,ITEM],
	0x9f11:['Issuer Code Table Index',BINARY,ITEM],
	0x9f12:['Application Preferred Name',TEXT,ITEM],
	0x9f1a:['Terminal Country Code',BINARY,VALUE],
	0x9f1f:['Track 1 Discretionary Data',TEXT,ITEM],
	0x9f20:['Track 2 Discretionary Data',TEXT,ITEM],
	0x9f26:['Application Cryptogram',BINARY,ITEM],
	0x9f32:['Issuer Public Key Exponent',BINARY,ITEM],
	0x9f36:['Application Transaction Counter',BINARY,ITEM],
	0x9f37:['Unpredictable Number',BINARY,VALUE],
	0x9f38:['Processing Options Data Object List (PDOL)',BINARY,TEMPLATE],
	0x9f42:['Application Currency Code',NUMERIC,ITEM],
	0x9f44:['Application Currency Exponent',NUMERIC,ITEM],
	0x9f4a:['Static Data Authentication Tag List',BINARY,ITEM],
	0x9f4d:['Log Entry',BINARY,ITEM],
	0x9f66:['Card Production Life Cycle',BINARY,ITEM],
	0xbf0c:['File Control Information (FCI) Issuer Discretionary Data',BER_TLV,TEMPLATE],
	}

#// conflicting item - need to check
#// 0x9f38:['Processing Optional Data Object List',BINARY,ITEM],

# define BER-TLV masks

TLV_CLASS_MASK= {	
		0x00:'Universal class',
		0x40:'Application class',
		0x80:'Context-specific class',
		0xc0:'Private class',
		}

# if TLV_TAG_NUMBER_MASK bits are set, refer to next byte(s) for tag number
# otherwise it's b1-5
TLV_TAG_NUMBER_MASK= 0x1f

# if TLV_DATA_MASK bit is set it's a 'Constructed data object'
# otherwise, 'Primitive data object'
TLV_DATA_MASK= 	0x20
TLV_DATA_TYPE= ['Primitive data object','Constructed data object']

# if TLV_TAG_MASK is set another tag byte follows
TLV_TAG_MASK= 0x80
TLV_LENGTH_MASK= 0x80


# define AIP mask
AIP_MASK= {
	  0x01:'CDA Supported (Combined Dynamic Data Authentication / Application Cryptogram Generation)',
	  0x02:'RFU',
	  0x04:'Issuer authentication is supported',
	  0x08:'Terminal risk management is to be performed',
	  0x10:'Cardholder verification is supported',
	  0x20:'DDA supported (Dynamic Data Authentication)',
	  0x40:'SDA supported (Static Data Authentiction)',
	  0x80:'RFU'
	  }

# define dummy transaction values (see TAGS for tag names)
# for generate_ac
TRANS_VAL= {
	   0x9f02:[0x00,0x00,0x00,0x00,0x00,0x01],
	   0x9f03:[0x00,0x00,0x00,0x00,0x00,0x00],
	   0x9f1a:[0x08,0x26],
	   0x95:[0x00,0x00,0x00,0x00,0x00],
	   0x5f2a:[0x08,0x26],
	   0x9a:[0x08,0x04,0x01],
	   0x9c:[0x01],
	   0x9f37:[0xba,0xdf,0x00,0x0d]
	   }
	
# define SW1 return values
SW1_RESPONSE_BYTES= 0x61
SW1_WRONG_LENGTH= 0x6c
SW12_OK= [0x90,0x00]
SW12_NOT_SUPORTED= [0x6a,0x81]
SW12_NOT_FOUND= [0x6a,0x82]
SW12_COND_NOT_SAT= [0x69,0x85]		# conditions of use not satisfied 
PIN_BLOCKED= [0x69,0x83]
PIN_BLOCKED2= [0x69,0x84]
PIN_WRONG= 0x63

# some human readable error messages
ERRORS= {
	'6700':"Not known",
	'6985':"Conditions of use not satisfied or Command not supported",
	'6984':"PIN Try Limit exceeded"
	}

# define GET_DATA primitive tags
PIN_TRY_COUNTER= [0x9f,0x17]
ATC= [0x9f,0x36]
LAST_ATC= [0x9f,0x13]
LOG_FORMAT= [0x9f, 0x4f]

# define TAGs after BER-TVL decoding
BER_TLV_AIP= 0x02
BER_TLV_AFL= 0x14 

def printhelp():
	print '\nChAP.py - Chip And PIN in Python'
	print 'Ver 0.1c\n'
	print 'usage:\n\n ChAP.py [options] [PIN]'
	print
	print 'If the optional numeric PIN argument is given, the PIN will be verified (note that this' 
	print 'updates the PIN Try Counter and may result in the card being PIN blocked).'
	print '\nOptions:\n'
	print '\t-a\t\tBruteforce AIDs'
	print '\t-A\t\tPrint list of known AIDs'
	print '\t-d\t\tDebug - Show PC/SC APDU data'
	print '\t-e\t\tBruteforce EMV AIDs'
	print '\t-f\t\tBruteforce files'
	print '\t-h\t\tPrint detailed help message'
	print '\t-o\t\tOutput to files ([AID]-FILExxRECORDxx.HEX)'
	print '\t-p\t\tBruteforce primitives'
	print '\t-r\t\tRaw output - do not interpret EMV data'
	print '\t-t\t\tUse T1 protocol (default is T0)'
	print '\t-v\t\tVerbose on'
        print

def hexprint(data):
	index= 0

	while index < len(data):
		print '%02x' % data[index],
		index += 1
	print

def get_tag(data,req):
	"return a tag's data if present"

	index= 0

	# walk the tag chain to ensure no false positives
	while index < len(data):
		try:
			# try 1-byte tags
			tag= data[index]	
			TAGS[tag]
			taglen= 1
		except:
			try:
				# try 2-byte tags
				tag= data[index] * 256 + data[index+1]
				TAGS[tag]
				taglen= 2
			except:
				# tag not found
				index += 1
				continue
		if tag == req:
			itemlength= data[index + taglen]
			index += taglen + 1
			return True, itemlength, data[index:index + itemlength]
		else:
			index += taglen + 1
	return False,0,''

def isbinary(data):
	index= 0

	while index < len(data):
		if data[index] < 0x20 or data[index] > 0x7e:
			return True
		index += 1
	return False

def decode_pse(data):
	"decode the main PSE select response"

	index= 0
	indent= ''

	if OutputFiles:
		file= open('%s-PSE.HEX' % CurrentAID,'w')
		for n in range(len(data)):
			file.write('%02X' % data[n])
		file.flush()
		file.close()

		
	if RawOutput:
		hexprint(data)
		textprint(data)
		return

	while index < len(data):
		try:
			tag= data[index]
			TAGS[tag]
			taglen= 1
		except:
			try:
				tag= data[index] * 256 + data[index+1]
				TAGS[tag]
				taglen= 2
			except:
				print indent + '  Unrecognised TAG:', 
				hexprint(data[index:])
				return
		print indent + '  %0x:' % tag, TAGS[tag][0],
		if TAGS[tag][2] == VALUE:
			itemlength= 1
			offset= 0
		else:
			itemlength= data[index + taglen]
			offset= 1
		print '(%d bytes):' % itemlength,
		# store CDOLs for later use
		if tag == CDOL1:
			Cdol1= data[index + taglen:index + taglen + itemlength + 1]
		if tag == CDOL2:
			Cdol2= data[index + taglen:index + taglen + itemlength + 1]
		out= ''
		mixedout= []
		while itemlength > 0:
			if TAGS[tag][1] == BER_TLV:
				print 'skipping BER-TLV object!'
				return
				#decode_ber_tlv_field(data[index + taglen + offset:])
			if TAGS[tag][1] == BINARY or TAGS[tag][1] == VALUE:
					if TAGS[tag][2] != TEMPLATE or Verbose:
						print '%02x' % data[index + taglen + offset],
			else: 
				if TAGS[tag][1] == NUMERIC:
					out += '%02x' % data[index + taglen + offset]
				else:
					if TAGS[tag][1] == TEXT:
						out += "%c" % data[index + taglen + offset]
					if TAGS[tag][1] == MIXED:
						mixedout.append(data[index + taglen + offset])
			itemlength -= 1
			offset += 1
		if TAGS[tag][1] == MIXED:
			if isbinary(mixedout):
				hexprint(mixedout)
			else:
				textprint(mixedout)
		if TAGS[tag][1] == BINARY:
			print
		if TAGS[tag][1] == TEXT or TAGS[tag][1] == NUMERIC:
			print out,
			if tag == 0x9f42 or tag == 0x5f28:
				print '(' + ISO3166CountryCodes['%03d' % int(out)] + ')'
			else:
				print
		if TAGS[tag][2] == ITEM:
			index += data[index + taglen] + taglen + 1
		else:
			index += taglen + 1
#			if TAGS[tag][2] != VALUE:
#				indent += '   ' 
	indent= ''

def textprint(data):
	index= 0
	out= ''

	while index < len(data):
		if data[index] >= 0x20 and data[index] < 0x7f:
			out += chr(data[index])
		else:
			out += '.'
		index += 1
	print out

def bruteforce_primitives():
	for x in range(256):
		for y in range(256):
			status, length, response= get_primitive([x,y])
			if status:
				print 'Primitive %02x%02x: ' % (x,y)
				if response:
					hexprint(response)
					textprint(response)

def get_primitive(tag):
	# get primitive data object - return status, length, data
	le= 0x00
	apdu = GET_DATA + tag + [le]
	response, sw1, sw2 = send_apdu(apdu)
	if response[0:2] == tag:
		length= response[2]
		return True, length, response[3:]
	else:
		return False, 0, ''

def check_return(sw1,sw2):
	if [sw1,sw2] == SW12_OK:
		return True
	return False

def send_apdu(apdu):
	# send apdu and get additional data if required 
	response, sw1, sw2 = cardservice.connection.transmit( apdu, Protocol )
	if sw1 == SW1_WRONG_LENGTH:
		# command used wrong length. retry with correct length.
		apdu= apdu[:len(apdu) - 1] + [sw2]
		return send_apdu(apdu)
	if sw1 == SW1_RESPONSE_BYTES:
		# response bytes available.
		apdu = GET_RESPONSE + [sw2]
		response, sw1, sw2 = cardservice.connection.transmit( apdu, Protocol )
	return response, sw1, sw2

def select_aid(aid):
	# select an AID and return True/False plus additional data
	apdu = SELECT + [len(aid)] + aid + [0x00]
	response, sw1, sw2= send_apdu(apdu)
	if check_return(sw1,sw2):
		if Verbose:
			decode_pse(response)
		return True, response, sw1, sw2
	else:
		return False, [], sw1,sw2

def bruteforce_aids(aid):
	#brute force two digits of AID
	print 'Bruteforcing AIDs'
	y= z= 0
	if BruteforceEMV:
		brute_range= [0xa0]
	else:
		brute_range= range(256)
	for x in brute_range:
		for y in range(256):
			for z in range(256):
				#aidb= aid + [x]
				aidb= [x,y,0x00,0x00,z]
				if Verbose:
					print '\r  %02x %02x %02x %02x %02x' % (x,y,0x00,0x00,z),
				status, response, sw1, sw2= select_aid(aidb)
				if [sw1,sw2] != SW12_NOT_FOUND:
					print '\r  Found AID:',
					hexprint(aidb)
					if status:
						decode_pse(response)
					else:
						print 'SW1 SW2: %02x %02x' % (sw1,sw2)

def read_record(sfi,record):
	# read a specific record from a file
	p1= record
	p2= (sfi << 3) + 4
	le= 0x00
	apdu= READ_RECORD + [p1,p2,le]
	response, sw1, sw2= send_apdu(apdu)
	if check_return(sw1,sw2):
		return True, response
	else:
		return False, ''

def bruteforce_files():
	# now try and brute force records
	print '  Checking for files:'
	for y in range(1,31):
		for x in range(1,256):
			ret, response= read_record(y,x)
			if ret:
				print "  Record %02x, File %02x: length %d" % (x,y,len(response))
				if Verbose:
					hexprint(response)
					textprint(response)
				decode_pse(response)

def get_processing_options():
	apdu= GET_PROCESSING_OPTIONS
	response, sw1, sw2= send_apdu(apdu)
	if check_return(sw1,sw2):
		return True, response
	else:
		return False, "%02x%02x" % (sw1,sw2)

def decode_processing_options(data):
	# extract and decode AIP (Application Interchange Profile)
	# and AFL (Application File Locator)
	if data[0] == 0x80:
		# data is in response format 1
		# first two bytes after length byte are AIP
		decode_aip(data[2:])
		# remaining data is AFL
		x= 4
		while x < len(data):
			sfi, start, end, offline= decode_afl(data[x:x+4])
			print '    SFI %02X: starting record %02X, ending record %02X; %02X offline data authentication records' % (sfi,start,end,offline)
			x += 4
			decode_file(sfi,start,end)
	if data[0] == 0x77:
		# data is in response format 2 (BER-TLV)
		x= 2
		while x < len(data):
			tag, fieldlen, value= decode_ber_tlv_item(data[x:])
			print '-- Value: ', hexprint(value)
			if tag == BER_TLV_AIP:
				decode_aip(value)
			if tag == BER_TLV_AFL:
				sfi, start, end, offline= decode_afl(value)
				print '    SFI %02X: starting record %02X, ending record %02X; %02X offline data authentication records' % (sfi,start,end,offline)
				decode_file(sfi,start,end)
			x += fieldlen

def decode_file(sfi,start,end):
	for y in range(start,end + 1):
		ret, response= read_record(sfi,y)
		if ret:
			if OutputFiles:
				file= open('%s-FILE%02XRECORD%02X.HEX' % (CurrentAID,sfi,y),'w')
				for n in range(len(response)):
					file.write('%02X' % response[n])
				file.flush()
				file.close()
			print '      record %02X: ' % y,
			decode_pse(response)
		else:
			print 'Read error!'


def decode_aip(data):
	# byte 1 of AIP is bit masked, byte 2 is RFU
	for x in AIP_MASK.keys():
		if data[0] & x:
			print '    ' + AIP_MASK[x]

def decode_afl(data):
	print '-- deccode_afl data: ', hexprint(data)
	sfi= int(data[0] >> 3)
	start= int(data[1])
	end= int(data[2])
	offline= int(data[3])
	return sfi, start, end, offline

def decode_ber_tlv_field(data):
	x= 0
	while x < len(data):
		tag, fieldlen, value= decode_ber_tlv_item(data[x:])
		print 'Tag %04X: ' % tag,
		hexprint(value)
		x += fieldlen

def decode_ber_tlv_item(data):
	# return tag, total length of data processed and value for BER-TLV object
	tag= data[0] & TLV_TAG_NUMBER_MASK
	i= 1
	if tag == TLV_TAG_NUMBER_MASK:
		tag= ''
		while data[i] & TLV_TAG_MASK:
			# another tag byte follows
			tag.append(xor(data[i],TLV_TAG_MASK))
			i += 1
		tag.append(data[i])
		i += 1
	if data[i] & TLV_LENGTH_MASK:
		# this byte tells us the number of subsequent bytes that describe the length
		lenlen= xor(data[i],TLV_LENGTH_MASK)
		i += 1
		length= int(data[i])
		z= 1
		while z < lenlen:
			i += 1
			z += 1
			length= length << 8
			length += int(data[i]) 
		i += 1
	else:
		length= int(data[i])
		i += 1
	return tag, i + length, data[i:i+length]

def get_challenge(bytes):
	lc= bytes
	le= 0x00
	apdu= GET_CHALLENGE + [lc,le]
	response, sw1, sw2= send_apdu(apdu)
	if check_return(sw1,sw2):
		print 'Random number: ',
		hexprint(response)
	#print 'GET CHAL: %02x%02x %d' % (sw1,sw2,len(response))

def verify_pin(pin):
	# construct offline PIN block and verify (plaintext)
	print 'Verifying PIN:',pin
	control= 0x02
	pinlen= len(pin)
	block= []
	block.append((control << 4) + pinlen)
	x= 0
	while x < len(pin):
		leftnibble= int(pin[x])
		try:
			rightnibble= int(pin[x + 1])	
		except:
			# pad to even length
			rightnibble= 0x0f
		block.append((leftnibble << 4) + rightnibble)
		x += 2
	while(len(block) < 8):
		block.append(0xff)
	lc= len(block)
	apdu= VERIFY + [lc] + block
	response, sw1, sw2= send_apdu(apdu)
	if check_return(sw1,sw2):
		print 'PIN verified'
		return True
	else:
		if [sw1,sw2] == PIN_BLOCKED or [sw1,sw2] == PIN_BLOCKED2:
			print 'PIN blocked!'
		else:
			if sw1 == PIN_WRONG:
				print 'wrong PIN - %d tries left' % (int(sw2) & 0x0f)
			if [sw1,sw2] == SW12_NOT_SUPORTED:
				print 'Function not supported'
			else:
				print 'command failed!', 
				hexprint([sw1,sw2])
	return False

def update_pin_try_counter(tries):
	# try to set Pin Try Counter by sending Card Status Update
	if tries > 0x0f:
		return False, 'PTC max value exceeded'
	csu= []
	csu.append(tries)
	csu.append(0x10)
	csu.append(0x00)
	csu.append(0x00)
	tag= 0x91 # Issuer Authentication Data
	lc= len(csu) + 1

def generate_ac(type):
	# generate an application Cryptogram
	if type == TC:
		# populate data with CDOL1
		print 
	apdu= GENERATE_AC + [lc,type] + data + [le]
	le= 0x00
	response, sw1, sw2= send_apdu(apdu)
	if check_return(sw1,sw2):
		print 'AC generated!'
		return True
	else:
		hexprint([sw1,sw2])
	

# main loop
aidlist= KNOWN_AIDS

try:
	# 'args' will be set to remaining arguments (if any)
	opts, args  = getopt.getopt(sys.argv[1:],'aAdefoprtv')
	for o, a in opts:
		if o == '-a':
			BruteforceAID= True
		if o == '-A':
			print
			for x in range(len(aidlist)):
				print '% 20s: ' % aidlist[x][0],
				hexprint(aidlist[x][1:])
			print
			sys.exit(False)	
		if o == '-d':
			Debug= True
		if o == '-e':
			BruteforceAID= True
			BruteforceEMV= True
		if o == '-f':
			BruteforceFiles= True
		if o == '-o':
			OutputFiles= True
		if o == '-p':
			BruteforcePrimitives= True
		if o == '-r':
			RawOutput= True
		if o == '-t':
			Protocol= CardConnection.T1_protocol
		if o == '-v':
			Verbose= True

except getopt.GetoptError:
	# -h will cause an exception as it doesn't exist!
	printhelp()
	sys.exit(True)

PIN= ''
if args:
	if not args[0].isdigit():
		print 'Invalid PIN', args[0]
		sys.exit(True)
	else:
		PIN= args[0]

try:
	# request any card type
	cardtype = AnyCardType()
	# request card insertion
	print 'insert a card within 10s'
	cardrequest = CardRequest( timeout=10, cardType=cardtype )
	cardservice = cardrequest.waitforcard()

	# attach the console tracer
	if Debug:
		observer=ConsoleCardConnectionObserver()
    		cardservice.connection.addObserver( observer )

	# connect to the card
	cardservice.connection.connect(Protocol)

	#get_challenge(0)

	# try to select PSE
	apdu = SELECT + [len(DF_PSE)] + DF_PSE
	response, sw1, sw2 = send_apdu( apdu )

	if check_return(sw1,sw2):
		# there is a PSE
		print 'PSE found!'
		decode_pse(response)
		if BruteforcePrimitives:
			# brute force primitives
			print 'Brute forcing primitives'
			bruteforce_primitives()
		if BruteforceFiles:
			print 'Brute forcing files'
			bruteforce_files()
		status, length, psd= get_tag(response,SFI)
		if not status:
			print 'No PSD found!'
		else:
			print '  Checking for records:',
			if BruteforcePrimitives:
				psd= range(31)
				print '(bruteforce all files)'
			else:
				print
			for x in range(256):
				for y in psd:
					p1= x
					p2= (y << 3) + 4
					le= 0x00
					apdu= READ_RECORD + [p1] + [p2,le]
					response, sw1, sw2 = cardservice.connection.transmit( apdu )
					if sw1 == 0x6c:
						print "  Record %02x, File %02x: length %d" % (x,y,sw2)
						le= sw2
						apdu= READ_RECORD + [p1] + [p2,le]
						response, sw1, sw2 = cardservice.connection.transmit( apdu )
						print "  ",
						aid= ''
						if Verbose:
							hexprint(response)
							textprint(response)
						i= 0
						while i < len(response):
							# extract the AID
							if response[i] == 0x4f and aid == '':
								aidlen= response[i + 1]
								aid= response[i + 2:i + 2 + aidlen]
							i += 1
						print '   AID found:',
						hexprint(aid)
						aidlist.append(['PSD Entry']+aid)
	if BruteforceAID:
		bruteforce_aids(BRUTE_AID)
	if aidlist:
		# now try dumping the AID records
		current= 0
		while current < len(aidlist):
			if Verbose:
				print 'Trying AID: %s -' % aidlist[current][0],
				hexprint(aidlist[current][1:])
			selected, response, sw1, sw2= select_aid(aidlist[current][1:])
			if selected:
				CurrentAID= ''
				for n in range(len(aidlist[current][1:])):
					CurrentAID += '%02X' % aidlist[current][1:][n]
				if Verbose:
					print '  Selected: ',
					hexprint(response)
					textprint(response)
				else:
					print '  Found AID: %s -' % aidlist[current][0],
					hexprint(aidlist[current][1:])
				decode_pse(response)
				if BruteforcePrimitives:
					# brute force primitives
					print 'Brute forcing primitives'
					bruteforce_primitives()
				if BruteforceFiles:
					print 'Brute forcing files'
					bruteforce_files()
				ret, response= get_processing_options()
				if ret:
					print '  Processing Options:',
					decode_pse(response)						
					decode_processing_options(response)
				else:
					print '  Could not get processing options:', response, ERRORS[response]
				ret, length, pins= get_primitive(PIN_TRY_COUNTER)
				if ret:
					ptc= int(pins[0])
					print '  PIN tries left:', ptc
					#if ptc == 0:
					#	print 'unblocking PIN'
					#	update_pin_try_counter(3)
					#	ret, sw1, sw2= send_apdu(UNBLOCK_PIN)
					#	hexprint([sw1,sw2])
				if PIN:
					if verify_pin(PIN):
						sys.exit(False)
					else:
						sys.exit(True)
				ret, length, atc= get_primitive(ATC)
				if ret:
					atcval= (atc[0] << 8) + atc[1]
					print '  Application Transaction Counter:', atcval
				ret, length, latc= get_primitive(LAST_ATC)
				if ret:
					latcval= (latc[0] << 8) + latc[1]
					print '  Last ATC:', latcval
				ret, length, logf= get_primitive(LOG_FORMAT)
				if ret:
					print 'Log Format: ',
					hexprint(logf)
				current += 1
			else:
				if Verbose:
					print '  Not found: %02x %02x' % (sw1,sw2)
				current += 1
	else:
		print 'no PSE: %02x %02x' % (sw1,sw2)

except CardRequestTimeoutException:
	print 'time-out: no card inserted during last 10s'

if 'win32'==sys.platform:
	print 'press Enter to continue'
	sys.stdin.read(1)
