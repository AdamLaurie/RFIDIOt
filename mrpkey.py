#!/usr/bin/python


#  mrpkey.py - calculate 3DES key for Machine Readable Passport
# 
#  Adam Laurie <adam@algroup.co.uk>
#  http://rfidiot.org/
# 
#  This code is copyright (c) Adam Laurie, 2006, 2007, All rights reserved.
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

STRIP_INDEX=True
DEBUG= False
Filetype= ''
DocumentType= '?'
Fields= ()
FieldNames= ()
FieldLengths= ()
FieldKeys= ()

# this needs fixing - MAX should be able to go up to size supported by device
MAXCHUNK= 118

import rfidiot
import sys
import os
import commands
from Crypto.Hash import SHA
from Crypto.Cipher import DES3
from Crypto.Cipher import DES
import string
from operator import *
import StringIO
from Tkinter import *
import Image
import ImageTk

# Machine Readable Document types
DOC_UNDEF= {
	   '?':'Undefined',
	   }

DOC_ID= {
	'I<':'ID Card',
	'IR':'ID Card',
	}

DOC_PASS=  {
	   'P<':'Passport',
	   'PM':'Passport',
	   'PA':'Passport',
	   'PV':'Passport',
	   }

DOCUMENT_TYPE= {}

# TEST data
TEST_MRZ= 'L898902C<3UTO6908061F9406236ZE184226B<<<<<14'
TEST_rnd_ifd= '781723860C06C226'
TEST_rnd_icc= '4608F91988702212'
TEST_Kifd= '0B795240CB7049B01C19B33E32804F0B'
TEST_respdata= '46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F2F2D235D074D7449'
MRZ_WEIGHT= [7,3,1]
APDU_OK= '9000'
APDU_BAC= '6982'

# Data Groups and Elements
EF_COM= '60'
EF_DG1= '61'
EF_DG2= '75'
EF_DG3= '63'
EF_DG4= '76'
EF_DG5= '65'
EF_DG6= '66'
EF_DG7= '67'
EF_DG8= '68'
EF_DG9= '69'
EF_DG10= '6a'
EF_DG11= '6b'
EF_DG12= '6c'
EF_DG13= '6d'
EF_DG14= '6e'
EF_DG15= '6f'
EF_DG16= '70'
EF_SOD= '77'
EF_TAGS= '5c'

# Data Group Names
TAG_NAME= {EF_COM:'EF.COM Data Group Presence Map',\
	   EF_DG1:'EF.DG1 Data Recorded in MRZ',\
	   EF_DG2:'EF.DG2 Encoded Identification Features - FACE',\
	   EF_DG3:'EF.DG3 Encoded Identification Features - FINGER(s)',\
	   EF_DG4:'EF.DG4 Encoded Identification Features - IRIS(s)',\
	   EF_DG5:'EF.DG5 Displayed Identification Feature(s) - PORTRAIT',\
	   EF_DG6:'EF.DG6 Reserved for future use',\
	   EF_DG7:'EF.DG7 Displayed Identification Features - SIGNATURE or USUAL MARK',\
	   EF_DG8:'EF.DG8 Encoded Security Features - DATA FEATURE(s)',\
	   EF_DG9:'EF.DG9 Encoded Security Features - STRUCTURE FEATURE(s)',\
	   EF_DG10:'EF.DG10 Encoded Security Features - SUBSTANCE FEATURE(s)',\
	   EF_DG11:'EF.DG11 Additional Personal Detail(s)',\
	   EF_DG12:'EF.DG12 Additional Document Detail(s)',\
	   EF_DG13:'EF.DG13 Optional Detail(s)',\
	   EF_DG14:'EF.DG14 Reserved for Future Use',\
	   EF_DG15:'EF.DG15 Active Authentication Public Key Info',\
	   EF_DG16:'EF.DG16 Person(s) to Notify',\
	   EF_SOD:'EF.SOD Document Security Object',\
	   EF_TAGS:'Tag List'}

# Data Group Passport Application Long FID
TAG_FID=  {EF_COM:'011E',\
	   EF_DG1:'0101',\
	   EF_DG2:'0102',\
	   EF_DG3:'0103',\
	   EF_DG4:'0104',\
	   EF_DG5:'0105',\
	   EF_DG6:'0106',\
	   EF_DG7:'0107',\
	   EF_DG8:'0108',\
	   EF_DG9:'0109',\
	   EF_DG10:'010A',\
	   EF_DG11:'010B',\
	   EF_DG12:'010C',\
	   EF_DG13:'010D',\
	   EF_DG14:'010E',\
	   EF_DG15:'010F',\
	   EF_DG16:'0110',\
	   EF_SOD:'011D'}

# Filesystem paths
tempfiles= '/tmp/'
filespath= ''

# Data Group filenames for local storage
TAG_FILE= {EF_COM:'EF_COM.BIN',\
	   EF_DG1:'EF_DG1.BIN',\
	   EF_DG2:'EF_DG2.BIN',\
	   EF_DG3:'EF_DG3.BIN',\
	   EF_DG4:'EF_DG4.BIN',\
	   EF_DG5:'EF_DG5.BIN',\
	   EF_DG6:'EF_DG6.BIN',\
	   EF_DG7:'EF_DG7.BIN',\
	   EF_DG8:'EF_DG8.BIN',\
	   EF_DG9:'EF_DG9.BIN',\
	   EF_DG10:'EF_DG10.BIN',\
	   EF_DG11:'EF_DG11.BIN',\
	   EF_DG12:'EF_DG12.BIN',\
	   EF_DG13:'EF_DG13.BIN',\
	   EF_DG14:'EF_DG14.BIN',\
	   EF_DG15:'EF_DG15.BIN',\
	   EF_DG16:'EF_DG16.BIN',\
	   EF_SOD:'EF_SOD.BIN'}

# Flags filenames for local storage
NOBAC_FILE='NOBAC'

# Data Group 1 Elements
DG1_ELEMENTS= {EF_DG1:'EF.DG1',\
	       '5f01':'LDS Version number with format aabb, where aa defines the version of the LDS and bb defines the update level',\
	       '5f36':'Unicode Version number with format aabbcc, where aa defines the Major version, bb defines the Minor version and cc defines the release level',\
	       '5c':'Tag list. List of all Data Groups present.'}
# Data Group 2 Elements
BDB= '5f2e'
BDB1= '7f2e'
FAC= '46414300'
DG2_ELEMENTS= {EF_DG2:'EF.DG2',\
	       '7f61':'Biometric Information Group Template',\
	       '02':'Integer - Number of instances of this type of biometric',\
	       '7f60':'1st Biometric Information Template',\
	       'a1':'Biometric Header Template (BHT)',\
	       '80':'ICAO header version [01 00] (Optional) - Version of the CBEFF patron header format',\
	       '81':'Biometric type (Optional)',\
	       '82':'Biometric feature (Optional for DG2, mandatory for DG3, DG4.)',\
	       '83':'Creation date and time (Optional)',\
	       '84':'Validity period (from through) (Optional)',\
	       '86':'Creator of the biometric reference data (PID) (Optional)',\
	       '87':'Format owner (Mandatory)',\
	       '88':'Format type (Mandatory)',\
	       BDB:'Biometric data (encoded according to Format Owner) also called the biometric data block (BDB).',\
	       BDB1:'Biometric data (encoded according to Format Owner) also called the biometric data block (BDB).',\
	       '7f60':'2nd Biometric Information Template',\
	       FAC:'Format Identifier ASCII FAC\0'}
# Data Group 2 field types
TEMPLATE= 0
SUB= 1
DG2_TYPE= {EF_DG2:TEMPLATE,\
	     '7f61':TEMPLATE,\
	     '02':SUB,\
	     '7f60':TEMPLATE,\
	     'a1':TEMPLATE,\
	     '80':SUB,\
	     '81':SUB,\
	     '82':SUB,\
	     '83':SUB,\
	     '84':SUB,\
	     '86':SUB,\
	     '87':SUB,\
	     '88':SUB,\
	     '5f2e':TEMPLATE,\
	     '7f2e':TEMPLATE,\
	     '7f60':TEMPLATE}

# ISO 19794_5 (Biometric identifiers)
ISO19794_5_GENDER= { '00':'Unpecified',\
		     '01':'Male',\
		     '02':'Female',\
		     '03':'Unknown',\
		     'ff':'Other'}

ISO19794_5_EYECOLOUR= { '00':'Unspecified',\
			'01':'Black',\
			'02':'Blue',\
			'03':'Brown',\
			'04':'Grey',\
			'05':'Green',\
			'06':'Multi',\
			'07':'Pink',\
			'08':'Other'}

ISO19794_5_HAIRCOLOUR= { '00':'Unspecified',\
			 '01':'Bald',\
			 '02':'Black',\
			 '03':'Blonde',\
			 '04':'Brown',\
			 '05':'Grey',\
			 '06':'White',\
			 '07':'Red',\
			 '08':'Green',\
			 '09':'Blue',\
			 'ff':'Other'}	

ISO19794_5_FEATURE= {0x01:'Specified',\
		     0x02:'Glasses',\
		     0x04:'Moustache',\
		     0x08:'Beard',\
		     0x10:'Teeth Visible',\
		     0x20:'Blink',\
		     0x40:'Mouth Open',\
		     0x80:'Left Eyepatch',\
		     0x100:'Right Eyepatch',\
		     0x200:'Dark Glasses',\
		     0x400:'Distorted'}

ISO19794_5_EXPRESSION= {'0000':'Unspecified',\
			'0001':'Neutral',\
		  	'0002':'Smile Closed',\
		  	'0003':'Smile Open',\
		  	'0004':'Raised Eyebrow',\
		  	'0005':'Looking Away',\
		  	'0006':'Squinting',\
		  	'0007':'Frowning'}

ISO19794_5_IMG_TYPE= {'00':'Unspecified (Front)',\
		      '01':'Basic',\
		      '02':'Full Front',\
		      '03':'Token Front',\
		      '04':'Other'}

ISO19794_5_IMG_DTYPE= {'00':'JPEG',\
		       '01':'JPEG 2000'}

ISO19794_5_IMG_FTYPE= {'00':'JPG',\
		       '01':'JP2'}

ISO19794_5_IMG_CSPACE= {'00':'Unspecified',\
			'01':'RGB24',\
			'02':'YUV422',\
			'03':'GREY8BIT',\
			'04':'Other'}

ISO19794_5_IMG_SOURCE= {'00':'Unspecified',\
			'01':'Static Unspecified',\
			'02':'Static Digital',\
			'03':'Static Scan',\
			'04':'Video Unknown',\
			'05':'Video Analogue',\
			'06':'Video Digital',\
			'07':'Unknown'}

ISO19794_5_IMG_QUALITY= {'00':'Unspecified'}

DG7_ELEMENTS= {EF_DG7:'EF.DG7',\
	       '5f43':'Displayed signature or mark',\
	       '02':'Integer - Number of instances of this type of displayed image'}

# display options
# standard document
MRZ_FIELD_NAMES= ('Document code','Issuing State or Organisation','Name','Passport Number','Check Digit','Nationality','Date of Birth','Check Digit','Sex','Date of Expiry','Check Digit','Personal Number or other optional elements','Check Digit','Composite Check Digit')
MRZ_FIELD_LENGTHS= (2,3,39,9,1,3,6,1,1,6,1,14,1,1)
MRZ_FIELD_DISPLAY= (0,3,1,2,5,6,8,9,11)
MRZ_FIELD_KEYS= (44,57,65)
# id card
MRZ_FIELD_NAMES_ID= ('Document code','Issuing State or Organisation','Document Number','Check Digit','Personal Number or other optional elements','Check Digit','Date of Birth','Check Digit','Sex','Date of Expiry','Check Digit','Nationality','Check Digit','Name')
MRZ_FIELD_LENGTHS_ID= (2,3,9,1,14,1,6,1,1,6,1,14,1,30)
MRZ_FIELD_DISPLAY_ID= (0,2,1,13,11,6,8,9,4)
MRZ_FIELD_KEYS_ID= (5,30,38)

# Global Send Sequence Counter
SSC= ''

# Global bruteforce vars
num= []
map= []
brnum= 0

def mrzspaces(data, fill):
	out= ''
	for x in range(len(data)):
		if data[x] == '<':
			out += fill
		else:
			out += data[x]
	return out

Displayed= False
Display_DG7= False
def drawfeatures(face,features):
	global Displayed
	global Style

	face.delete("feature")
	if Displayed:
		Displayed= False;
		return
	for item in features:
		x= int(item[4:8],16)
		y= int(item[8:12],16)
		if Style == 'Arrow':
			face.create_line(0,0,x,y,fill="Red",arrow="last",width=2,tags="feature")
		if Style == 'Cross':
			face.create_line(x-6,y-6,x+6,y+6,fill="Red",width=2, tags="feature")
			face.create_line(x-6,y+6,x+6,y-6,fill="Red",width=2, tags= "feature")
		if Style == 'Target':
			face.create_line(x,y-15,x,y+15,fill="Red",width=3, tags="feature")
			face.create_line(x-15,y,x+15,y,fill="Red",width=3, tags="feature")
			face.create_oval(x-6,y-6,x+6,y+6,fill="Red",tags="feature")
		if Style == 'Circle':
			face.create_oval(x-6,y-6,x+6,y+6,fill="Red", tags="feature")
		Displayed= True

def changestyle(style,face,features):
	global Style
	global Displayed

	Style= style
	if Displayed:
		Displayed= False
		drawfeatures(face,features)

def secure_select_file(keyenc, keymac,file):
	"secure select file"
	global SSC

	cla= '0c'
	ins= passport.ISOAPDU['SELECT_FILE']
	p1= '02'
	p2= '0c'
	command= passport.PADBlock(passport.ToBinary(cla + ins + p1 + p2))
	data= passport.PADBlock(passport.ToBinary(file))
	tdes= DES3.new(keyenc,DES.MODE_CBC,passport.DES_IV)
	encdata= tdes.encrypt(data)
	if DEBUG:
		print 'Encrypted data: ',
		passport.HexPrint(encdata)
	do87= passport.ToBinary(passport.DO87) + encdata
	m= command + do87
	if DEBUG:
		print 'DO87: ',
		passport.HexPrint(m)
	SSC= passport.SSCIncrement(SSC)
	n= SSC + m
	cc= passport.DESMAC(n,keymac,'')
	if DEBUG:
		print 'CC: ',
		passport.HexPrint(cc)
	do8e= passport.ToBinary(passport.DO8E) + cc
	if DEBUG:
		print 'DO8E: ',
		passport.HexPrint(do8e)
	lc= "%02x" % (len(do87) + len(do8e))
	le= '00'
	data= passport.ToHex(do87 + do8e)
	if DEBUG:
		print
		print 'Protected APDU: ',
		print cla+ins+p1+p2+lc+data+le
	ins= 'SELECT_FILE'
	if passport.send_apdu('','','','',cla,ins,p1,p2,lc,data,le):
		out= passport.data
	if DEBUG:
		print 'Secure Select:',
	if passport.errorcode == APDU_OK:
		if DEBUG:
			print 'OK'
		check_cc(keymac,out)
		return True, out
	else:
		return False, passport.errorcode

def secure_read_binary(keymac,bytes,offset):
	"secure read binary data"
	global SSC

	cla= '0c'
	ins= passport.ISOAPDU['READ_BINARY']
	hexoffset= '%04x' % offset
	p1= hexoffset[0:2]
	p2= hexoffset[2:4]
	le= '%02x' % bytes
	command= passport.PADBlock(passport.ToBinary(cla + ins + p1 + p2))
	do97= passport.ToBinary(passport.DO97 + le)
	m= command + do97 
	SSC= passport.SSCIncrement(SSC)
	n= SSC + m
	cc= passport.DESMAC(n,keymac,'')
	do8e= passport.ToBinary(passport.DO8E) + cc
	lc= "%02x" % (len(do97) + len(do8e))
	le= '00'
	data= passport.ToHex(do97 + do8e)
	if DEBUG:
		print
		print 'Protected APDU: ',
		print cla+ins+p1+p2+lc+data+le
	ins= 'READ_BINARY'
	if passport.send_apdu('','','','',cla,ins,p1,p2,lc,data,le):
		out= passport.data
	if DEBUG:
		print 'Secure Read Binary (%02d bytes): ' % bytes,
	if passport.errorcode == APDU_OK:
		if DEBUG:
			print 'OK:', out
		check_cc(keymac,out)
		return True, out
	else:
		return False, passport.errorcode 

def calculate_check_digit(data):
	"calculate ICAO 9303 check digit"
	cd= n= 0
	for d in data:
		if 'A' <= d <= 'Z':
			value = ord(d)-55
		elif d == '<':
			value = 0
		else:
			value = int(d)
		cd += value * MRZ_WEIGHT[n % 3]
		n += 1
	return '%s' % (cd % 10)

def check_cc(key,rapdu):
	"Check Cryptographic Checksum"
	global SSC

	SSC= passport.SSCIncrement(SSC)
	k= SSC
	length= 0
	# check if DO87 present
	if rapdu[0:2] == "87":
		length= 4 + int(rapdu[2:4],16) * 2
		k += passport.ToBinary(rapdu[:length])
	# check if DO99 present
	if rapdu[length:length + 2] == "99":
		length2= 4 + int(rapdu[length + 2:length + 4],16) * 2
		k += passport.ToBinary(rapdu[length:length + length2])
	
	if DEBUG:
		print 'K: ',
		passport.HexPrint(k)
	cc= passport.DESMAC(k,key,'')
	if DEBUG:
		print 'CC: ',
		print passport.ToHex(cc),
	if cc ==  passport.ToBinary(rapdu[len(rapdu) - len(cc) *2:]):
		if DEBUG:
        		print '(verified)'
		return True
	else:
        	print 'Cryptographic Checksum failed!'
        	print 'Expected CC: ',
        	passport.HexPrint(cc)
        	print 'Received CC: ',
        	print rapdu[len(rapdu) - len(cc) * 2:]
		os._exit(True)

def decode_ef_com(data):
	TAG_PAD= '80'

	# set up array for Data Groups to be read
	ef_groups= []

	"display contents of EF.COM"
	hexdata= passport.ToHex(data)
	# skip header
	pos= 2
	# EF.COM length
	print 'Length: ', asn1datalength(hexdata[pos:])
	pos += asn1fieldlength(hexdata[pos:])
	while pos < len(hexdata):
		# end of data
		if hexdata[pos:pos+2] == TAG_PAD:
			return
		# LDS & Unicode Versions
		decoded= False
		for length in 2,4:
                       	if DG1_ELEMENTS.has_key(hexdata[pos:pos + length]):
				decoded= True
				print '  tag:',hexdata[pos:pos + length],'('+DG1_ELEMENTS[hexdata[pos:pos+length]]+')'
				# decode tag list (stored objects)
				if hexdata[pos:pos+length] == EF_TAGS:
					pos += 2
					print '    length: ',
					length= asn1datalength(hexdata[pos:])
					print length
					pos += asn1fieldlength(hexdata[pos:])
					for n in range(length):
						print '      Data Group: ',
						print hexdata[pos:pos+2] + ' (' + TAG_NAME[hexdata[pos:pos+2]] + ')'
						ef_groups.append(hexdata[pos:pos+2])
						pos += 2
				else:
					pos += length
					fieldlength= asn1datalength(hexdata[pos:])
					print '    length:',fieldlength
					pos += asn1fieldlength(hexdata[pos:])
					print '    data:',hexdata[pos:pos+fieldlength*2]
					pos += fieldlength*2
		if not decoded:
			print 'Unrecognised element:', hexdata[pos:pos+4]
			os._exit(True)
	return ef_groups

def read_file(file):
	if not passport.iso_7816_select_file(file,passport.ISO_7816_SELECT_BY_EF,'0C'):
		return False, ''
	readlen= 4
	offset= 4
	if not passport.iso_7816_read_binary(readlen,0):
		return False, ''
	data= passport.data
	# get file length
	tag= data[:2]
	datalen= asn1datalength(data[2:])
	print 'File Length:', datalen
	# deduct length field and header from what we've already read
	readlen= datalen - (3 - asn1fieldlength(data[2:]) / 2)
	print 'Remaining data length:', readlen
	# read remaining bytes
	while readlen > 0:
		if readlen > MAXCHUNK:
			toread= MAXCHUNK
		else:
			toread= readlen
		if not passport.iso_7816_read_binary(toread,offset):
			return False, ''
		data+=passport.data
		offset += toread
		readlen -= toread
		print 'Reading: %05d\r' % readlen,
		sys.stdout.flush()
	print
	return True, data.decode('hex')

def asn1fieldlength(data):
	#return length of number field according to asn.1 rules (doubled as we normally care about the hex version)
	if int(data[:2],16) <= 0x7f:
		return 2
	if int(data[:2],16) == 0x81:
		return 4
	if int(data[:2],16) == 0x82:
		return 6

def asn1datalength(data):
	#return actual length represented by asn.1 field
	if int(data[:2],16) <= 0x7f:
		return int(data[:2],16)
	if int(data[:2],16) == 0x81:
		return  int(data[2:4],16)
	if int(data[:2],16) == 0x82:
		return int(data[2:6],16)

def secure_read_file(keyenc,keymac,file):
#	MAXCHUNK= int(passport.ISO_FRAMESIZE[passport.framesize])

	status, rapdu= secure_select_file(keyenc,keymac,file)
	if not status:
		return False, rapdu
	# secure read file header (header byte plus up to 3 bytes of field length)
	readlen= 4
	offset= 4
	status, rapdu= secure_read_binary(keymac,readlen,0)
	if not status:
		return False, rapdu
	do87= rapdu[6:22]
	if DEBUG:
		print 'DO87: ' + do87
		print 'Decrypted DO87: ',
	tdes=  DES3.new(keyenc,DES.MODE_CBC,passport.DES_IV)
	decdo87= tdes.decrypt(passport.ToBinary(do87))[:readlen]
	if DEBUG:
		passport.HexPrint(decdo87)

	# get file length
	do87hex= passport.ToHex(decdo87)
	tag= do87hex[:2]
	datalen= asn1datalength(do87hex[2:])
	print 'File Length:', datalen
	# deduct length field and header from what we've already read
	readlen= datalen - (3 - asn1fieldlength(do87hex[2:]) / 2)
	print 'Remaining data length:', readlen
	# secure read remaining bytes
	while readlen > 0:
		if readlen > MAXCHUNK:
			toread= MAXCHUNK
		else:
			toread= readlen
		status, rapdu= secure_read_binary(keymac,toread,offset)
		if not status:
			return rapdu
		do87= rapdu[6:(toread + (8 - toread % 8)) * 2 + 6]
		tdes=  DES3.new(keyenc,DES.MODE_CBC,passport.DES_IV)
		decdo87 += tdes.decrypt(passport.ToBinary(do87))[:toread]
		offset += toread
		readlen -= toread
		print 'Reading: %05d\r' % readlen,
		sys.stdout.flush()
	print
	return True, decdo87

def decode_ef_dg1(data):
	global DocumentType
	global DOCUMENT_TYPE
	global Fields
	global FieldNames
	global FieldLengths
	global FieldKeys

	length= int(passport.ToHex(data[4]),16)
	print 'Data Length: ',
	print length
	pointer= 5
	out= ''
	while pointer < len(data):
		if data[pointer] == chr(0x80):
			break
		out += '%s' % chr(int(passport.ToHex(data[pointer]),16))
		pointer += 1
	print '  Decoded Data: ' + out
	DocumentType= out[0:2]
	if DOC_ID.has_key(DocumentType):
		print '    Document type: %s' % DOC_ID[DocumentType]
		DOCUMENT_TYPE= DOC_ID
		Fields= MRZ_FIELD_DISPLAY_ID
		FieldNames= MRZ_FIELD_NAMES_ID
		FieldLengths= MRZ_FIELD_LENGTHS_ID
		FieldKeys= MRZ_FIELD_KEYS_ID
	else:
		print '    Document type: %s' % DOC_PASS[DocumentType]
		DOCUMENT_TYPE= DOC_PASS
		Fields= MRZ_FIELD_DISPLAY
		FieldNames= MRZ_FIELD_NAMES
		FieldLengths= MRZ_FIELD_LENGTHS
		FieldKeys= MRZ_FIELD_KEYS
	pointer= 0
	for n in range(len(FieldNames)):
		print '    ' + FieldNames[n] + ': ',
		print out[pointer:pointer + FieldLengths[n]]
		pointer += FieldLengths[n]
	return(out)

def decode_ef_dg2(data):
	global Filetype
	img_features= []

	datahex= passport.ToHex(data)
	position= 0
	end= len(datahex)
	while position < end:
		decoded= False
		# check for presence of tags
		for length in 4,2:
			if DG2_ELEMENTS.has_key(datahex[position:position + length]):
				decoded= True
				tag= datahex[position:position + length]
				print '  Tag:', tag, '('+DG2_ELEMENTS[tag]+')'
				# don't skip TEMPLATE fields as they contain sub-fields
				# except BDB which is a special case (CBEFF formatted) so for now
				# just try and extract the image which is 65 bytes in
				if DG2_TYPE[tag] == TEMPLATE:
					position += length
					fieldlength= asn1datalength(datahex[position:])
					print '     length:', fieldlength
					if tag == BDB or tag == BDB1:
						# process CBEFF block
						position += asn1fieldlength(datahex[position:])
						# FACE header
						length= len(FAC)
						tag= datahex[position:position + length]
						if not tag == FAC:
							print 'Missing FAC in CBEFF block: %s' % tag
							os._exit(True)
						position += length
						# FACE version
						print '    FACE version: %s' % passport.ToBinary(datahex[position:position + 6])
						position += 8
						# Image length
						print '      Record Length: %d' % int(datahex[position:position + 8],16)
						imagelength= int(datahex[position:position + 8],16)
						position += 8
						# Number of Images
						images= int(datahex[position:position + 4],16)
						print '      Number of Images: %d' % images
						position += 4
						# Facial Image block
						print '      Block Length: %d' % int(datahex[position:position + 8],16)
						position += 8
						features= int(datahex[position:position + 4],16)
						print '      Number of Features: %d' % features
						position += 4
						print '      Gender: %s' % ISO19794_5_GENDER[datahex[position:position + 2]]
						position += 2
						print '      Eye Colour: %s' % ISO19794_5_EYECOLOUR[datahex[position:position + 2]]
						position += 2
						print '      Hair Colour: %s' % ISO19794_5_HAIRCOLOUR[datahex[position:position + 2]]
						position += 2
						mask= int(datahex[position:position + 6],16)
						print '      Feature Mask: %s' % datahex[position:position + 6]
						position += 6
						if features:
							print '      Features:'
							for m, d in ISO19794_5_FEATURE.items():
								if and_(mask,m):
									print '        : %s' % d
						print '      Expression: %s' % ISO19794_5_EXPRESSION[datahex[position:position + 4]]
						position += 4
						print '      Pose Angle: %s' % datahex[position:position + 6]
						position += 6
						print '      Pose Angle Uncertainty: %s' % datahex[position:position + 6]
						position += 6
						while features > 0:
							print '      Feature block: %s' % datahex[position:position + 16]
							img_features.append(datahex[position:position + 16])
							features -= 1
							position += 16
						print '      Image Type: %s' % ISO19794_5_IMG_TYPE[datahex[position:position + 2]]
						position += 2
						print '      Image Data Type: %s' % ISO19794_5_IMG_DTYPE[datahex[position:position + 2]]
						Filetype= ISO19794_5_IMG_FTYPE[datahex[position:position + 2]]
						position += 2
						print '      Image Width: %d' % int(datahex[position:position + 4],16)
						position += 4
						print '      Image Height: %d' % int(datahex[position:position + 4],16)
						position += 4
						print '      Image Colour Space: %s' % ISO19794_5_IMG_CSPACE[datahex[position:position + 2]]
						position += 2
						print '      Image Source Type: %s' % ISO19794_5_IMG_SOURCE[datahex[position:position + 2]]
                                                position += 2
						print '      Image Device Type: %s' % datahex[position:position + 6]
                                                position += 6
						print '      Image Quality: %s' % ISO19794_5_IMG_QUALITY[datahex[position:position + 2]]
						position += 2
						img= open(tempfiles+'EF_DG2.' + Filetype,'wb+')
						img.write(data[position / 2:position + imagelength])
						img.flush()
						img.close()
						print '     JPEG image stored in %sEF_DG2.%s' % (tempfiles,Filetype)
						position += imagelength * 2
					else:
						position += asn1fieldlength(datahex[position:])
				else:
					position += length
					fieldlength= asn1datalength(datahex[position:])
					print '     length:', fieldlength
					position += asn1fieldlength(datahex[position:])
					print '     data:', datahex[position:position + fieldlength * 2]
					position += fieldlength * 2
		if not decoded:
			print 'Unrecognised element:', datahex[position:position + 4]
			os._exit(True)
	return img_features	

def decode_ef_dg7(data):
	global Filetype
	global Display_DG7
	datahex= passport.ToHex(data)
	position= 0
	end= len(datahex)
	while position < end:
		decoded= False
		# check for presence of tags
		for length in 4,2:
			if DG7_ELEMENTS.has_key(datahex[position:position + length]):
				decoded= True
				tag= datahex[position:position + length]
				print '  Tag:', tag, '('+DG7_ELEMENTS[tag]+')'
				position += length
				fieldlength= asn1datalength(datahex[position:])
				print '     length:', fieldlength
				if tag == '67':
					position += asn1fieldlength(datahex[position:])
				elif tag == '02':
					position += asn1fieldlength(datahex[position:])
					print '     content: %i instance(s)' % int(datahex[position:position + fieldlength * 2], 16)
					# note that for now we don't support decoding several instances...
					position += fieldlength * 2
				elif tag == '5f43':
					position += asn1fieldlength(datahex[position:])
					img= open(tempfiles+'EF_DG7.' + Filetype,'wb+')
					img.write(data[position / 2:position + fieldlength])
					img.flush()
					img.close()
					print '     JPEG image stored in %sEF_DG7.%s' % (tempfiles,Filetype)
					Display_DG7= True
					position += fieldlength * 2
		if not decoded:
			print 'Unrecognised element:', datahex[position:position + 4]
			os._exit(True)
	return

def jmrtd_create_file(file,length):
	"create JMRTD file"
	ins= 'CREATE_FILE'
	p1= '00'
	p2= '00'
	le= '06' # length is always 6
	data= "6304" + "%04x" % length + file
	if passport.send_apdu('','','','','',ins,p1,p2,le,data,''):
		return
	if passport.errorcode == '6D00':
		# could be a vonJeek card
		print "create file failed - assuming vonJeek emulator"
		return
	passport.iso_7816_fail(passport.errorcode)

def jmrtd_select_file(file):
	"select JMRTD file"
	ins= 'SELECT_FILE'
	p1= '00'
	p2= '00'
	data= "02" + file
	if passport.send_apdu('','','','','',ins,p1,p2,'',data,''):
		return
	if passport.errorcode == '6982':
		# try vonJeek
		print "selecting vonJeek file"
		ins= 'VONJEEK_SELECT_FILE'
		cla= '10'
		if passport.send_apdu('','','','',cla,ins,p1,p2,'',data,''):
			return
	passport.iso_7816_fail(passport.errorcode)

def jmrtd_write_file(file,data):
	"write data to JMRTD file"
	jmrtd_select_file(file)
	offset= 0
	towrite= len(data)
	while towrite:
		if towrite > MAXCHUNK:
			chunk= MAXCHUNK
		else:
			chunk= towrite
		print "\rwriting %d bytes       " % towrite,
		sys.stdout.flush()
		jmrtd_update_binary(offset,data[offset:offset + chunk])
		offset += chunk
		towrite -= chunk
	print

def jmrtd_update_binary(offset,data):
	"write a chunk of data to an offset within the currently selected JMRTD file"
	hexoff= "%04x" % offset
	ins= 'UPDATE_BINARY'
	p1= hexoff[0:2]
	p2= hexoff[2:4]
	lc= "%02x" % len(data)
	data= passport.ToHex(data)
	if passport.send_apdu('','','','','',ins,p1,p2,lc,data,''):
		return
	if passport.errorcode == '6D00':
		# vonJeek
		print "(vonJeek)",
		ins= 'VONJEEK_UPDATE_BINARY'
		cla= '10'
		if passport.send_apdu('','','','',cla,ins,p1,p2,lc,data,''):
			return
	passport.iso_7816_fail(passport.errorcode)

def jmrtd_personalise(documentnumber,dob,expiry):
	"set the secret key for JMRTD document"
	ins= 'PUT_DATA'
	p1= '00'
	p2= '62'
	data= '621B04' + "%02x" % len(documentnumber) + passport.ToHex(documentnumber) + '04' + "%02x" % len(dob) + passport.ToHex(dob) + '04' + "%02X" % len(expiry) + passport.ToHex(expiry)
	lc= "%02X" % (len(data) / 2)
	if passport.send_apdu('','','','','',ins,p1,p2,lc,data,''):
		return 
	if passport.errorcode == '6D00':
		# vonJeek
		cla= '10'
		ins= 'VONJEEK_SET_MRZ'
		data= passport.ToHex(documentnumber) +  passport.ToHex(calculate_check_digit(documentnumber)) + passport.ToHex(dob) + passport.ToHex(calculate_check_digit(dob)) + passport.ToHex(expiry) + passport.ToHex(calculate_check_digit(expiry))
		lc= "%02X" % (len(data) / 2)
		if passport.send_apdu('','','','',cla,ins,p1,p2,lc,data,''):
			# see if we need to set BAC or not, hacky way for now...
			if os.access(filespath+NOBAC_FILE,os.F_OK):
				BAC=False
			else:
				BAC=True
			if BAC:
				vonjeek_setBAC()
			else:
				vonjeek_unsetBAC()
			return
	passport.iso_7816_fail(passport.errorcode)

def vonjeek_setBAC():
	"enable BAC on vonjeek emulator card"
	# Setting BAC works only on recent vonJeek emulators, older have only BAC anyway
	print "Forcing BAC mode to ENABLED"
	if passport.send_apdu('','','','','10','VONJEEK_SET_BAC','00','01','00','',''):
		return
	else:
		print "ERROR Could not enable BAC, make sure you are using a recent vonJeek emulator"
		os._exit(True)

def vonjeek_unsetBAC():
	"disable BAC on vonjeek emulator card"
	print "Forcing BAC mode to DISABLED"
	if passport.send_apdu('','','','','10','VONJEEK_SET_BAC','00','00','00','',''):
		return
	else:
		print "ERROR Could not disable BAC, make sure you are using a recent vonJeek emulator"
		os._exit(True)

def jmrtd_lock():
	"set the JMRTD to Read Only"
	ins= 'PUT_DATA'
	p1= 'de'
	p2= 'ad'
	lc= '00'
	if passport.send_apdu('','','','','',ins,p1,p2,lc,'',''):
		return
	passport.iso_7816_fail(passport.errorcode)

def bruteno(init):
	global num
	global map
	global brnum
	global width

	if init:
		# set up brute force and return number of iterations required
		width= 0
		for x in range(len(init)):
			if init[x] == '?':
				width += 1
				num.append(0)
				map.append(True)
			else:
				num.append(init[x])
				map.append(False)
		return pow(10, width)
	else:
		out= ''
		bruted= False
		for x in range(len(num)):
			if map[x]:
				if bruted:
					continue
				else:
					bruted= True
					out += '%0*d' % (width, brnum)
					brnum += 1
			else:
				out += num[x]
		return out

try:
        passport= rfidiot.card
except:
        os._exit(True)

args= rfidiot.args
Help= rfidiot.help
Nogui= rfidiot.nogui
DEBUG= rfidiot.rfidiotglobals.Debug

myver= 'mrpkey v0.1t'
passport.info(myver)

TEST= False
FILES= False
bruteforce= False
bruteforceno= False
bruteforcereset= False
Jmrtd= False
JmrtdLock= False
MRZ=True
BAC=True
SETBAC=False
UNSETBAC=False

def help():
	print
	print 'Usage:'
	print '\t' + sys.argv[0] + ' [OPTIONS] <MRZ (Lower)|PLAIN|CHECK|[PATH]> [WRITE|WRITELOCK|SLOWBRUTE]'
	print
	print '\tSpecify the Lower MRZ as a quoted string or the word TEST to use sample data.'
	print '\tLower MRZ can be full line or shortened to the essentials: chars 1-9;14-19;22-27'
	print '\tSpecify the word PLAIN if the passport doesn\'t have BAC (shorthand for dummy MRZ)'
	print '\tSpecify the word CHECK to check if the device is a passport.'
	print '\tSpecify a PATH to use files that were previously read from a passport.'
	print '\tSpecify the option WRITE after a PATH to initialise a JMRTD or vonJeek emulator \'blank\'.'
	print '\tSpecify the option WRITELOCK after a PATH to initialise a JMRTD emulator \'blank\' and set to Read Only.'
	print '\tSpecify the option WRITE/WRITELOCK after a MRZ or PLAIN to clone a passport to a JMRTD or vonJeek emulator.'
	print '\tSpecify the option SETBAC   to enable  BAC on a (already configured) vonJeek emulator card.'
	print '\tSpecify the option UNSETBAC to disable BAC on a (already configured) vonJeek emulator card.'
	print '\tSpecify \'?\' for check digits if not known and they will be calculated.'
	print '\tSpecify \'?\' in the passport number field for bruteforce of that portion.'
	print '\tNote: only one contiguous portion of the field may be bruteforced.'
	print '\tSpecify the option SLOWBRUTE after MRZ to force reset between attempts (required on some new passports)'
	print '\tPadding character \'<\' should be used for unknown fields.'
	print
        os._exit(True)

if len(args) == 0 or Help:
	help()

arg0= args[0].upper()

if not(len(arg0) == 44 or len(arg0) == 21 or arg0 == 'TEST' or arg0 == 'CHECK' or arg0 == 'PLAIN' or arg0 == 'SETBAC' or arg0 == 'UNSETBAC' or os.access(args[0],os.F_OK)) or len(args) > 2:
	help()

if len(args) == 2:
        arg1= args[1].upper()
        if not (arg1 == 'WRITE' or arg1 == 'WRITELOCK' or arg1 == 'SLOWBRUTE'):
                help()

print

# check if we are reading from files
if os.access(args[0],os.F_OK):
	FILES= True
	filespath= args[0]
	if not filespath[len(filespath) - 1] == '/':
		filespath += '/'
	try:
		passfile= open(filespath + 'EF_COM.BIN','rb')
	except:
		print "Can't open %s" % (filespath + 'EF_COM.BIN')
		os._exit(True)
	data= passfile.read()
	eflist= decode_ef_com(data)
	raw_efcom= data
	passfile.close()

if arg0 == 'PLAIN' or len(arg0) == 44 or len(arg0) == 21 or FILES:
	if len(args) == 2:
		if arg1 == "WRITE":
			Jmrtd= True
		if arg1 == "WRITELOCK":
			Jmrtd= True
			JmrtdLock= True

if len(args) == 2 and arg1 == "SLOWBRUTE":
        bruteforcereset = True

if arg0 == 'TEST':
	TEST= True

if arg0 == 'SETBAC':
	MRZ=False
	SETBAC= True

if arg0 == 'UNSETBAC':
	MRZ=False
	UNSETBAC= True

if arg0 == 'CHECK':
	while not passport.hsselect('08', 'A') and not passport.hsselect('08', 'B'):
		print 'Waiting for passport... (%s)' % passport.errorcode
	if passport.iso_7816_select_file(passport.AID_MRTD,passport.ISO_7816_SELECT_BY_NAME,'0C'):
		print 'Device is a Machine Readable Document'
		os._exit(False)
	else:
		print 'Device may NOT be a Machine Readable Document'
		passport.iso_7816_fail(passport.errorcode)
		os._exit(True)

if arg0 == 'PLAIN':
	MRZ=False

if TEST:
	passport.MRPmrzl(TEST_MRZ)
	print 'Test MRZ: ' + TEST_MRZ
if not TEST and not FILES and MRZ:
	key=arg0
	# expands short MRZ version if needed
	if len(key) == 21:
		key= key[0:9] + 'XXXX' + key[9:15] + 'XX' + key[15:21] + 'XXXXXXXXXXXXXXXXX'
	passport.MRPmrzl(key)

if not FILES and not TEST:
	# set communication speed
	# 01 = 106 kBaud
	# 02 = 212 kBaud
	# 04 = 414 kBaud
	# 08 = 818 kBaud
	while 42:
                cardtype='A'
                if passport.hsselect('08', cardtype):
                        break
                cardtype='B'
                if passport.hsselect('08', cardtype):
                        break
		print 'Waiting for passport... (%s)' % passport.errorcode
	print 'Device set to %s transfers' % passport.ISO_SPEED[passport.speed]
	print 'Device supports %s Byte transfers' % passport.ISO_FRAMESIZE[passport.framesize]
	print
	print 'Select Passport Application (AID): ',
	if passport.iso_7816_select_file(passport.AID_MRTD,passport.ISO_7816_SELECT_BY_NAME,'0C'):
		print 'OK'
	else:
		passport.iso_7816_fail(passport.errorcode)
	print 'Select Master File: ',
	if passport.iso_7816_select_file(TAG_FID[EF_COM],passport.ISO_7816_SELECT_BY_EF,'0C'):
		# try forcing BAC by reading a file
		status, data= read_file(TAG_FID[EF_DG1])
		if not status and passport.errorcode == APDU_BAC:
			BAC=True
		else:
			print 'No Basic Access Control!'
			print passport.errorcode
			BAC=False
if BAC:
	print 'Basic Acces Control Enforced!'

if SETBAC:
	vonjeek_setBAC()
	os._exit(True)

if UNSETBAC:
	vonjeek_unsetBAC()
	os._exit(True)

if BAC and not MRZ:
	print 'Please provide a MRZ!'
	os._exit(True)

if not FILES and BAC:
	print 'Passport number: ' + passport.MRPnumber
	if passport.MRPnumber.find('?') >= 0:
		bruteforce= True
		bruteforceno= True
		# initialise bruteforce for number
		iterations= bruteno(passport.MRPnumber)
		print 'Bruteforcing Passport Number (%d iterations)' % iterations
	else:
		iterations= 1
	print 'Nationality: ' + passport.MRPnationality
	print 'Date Of Birth: ' + passport.MRPdob
	print 'Sex: ' + passport.MRPsex
	print 'Expiry: ' + passport.MRPexpiry
	print 'Optional: ' + passport.MRPoptional

	# loop until successful login breaks us out or we've tried all possibilities
	while iterations:
		iterations -= 1
		if bruteforceno:
			passport.MRPnumber= bruteno('')
		# always calculate check digits (makes bruteforcing easier)
		passport.MRPnumbercd= calculate_check_digit(passport.MRPnumber)
		passport.MRPdobcd= calculate_check_digit(passport.MRPdob)
		passport.MRPexpirycd= calculate_check_digit(passport.MRPexpiry)
		passport.MRPoptionalcd= calculate_check_digit(passport.MRPoptional)
		passport.MRPcompsoitecd= calculate_check_digit(passport.MRPnumber + passport.MRPnumbercd + passport.MRPdob + passport.MRPdobcd + passport.MRPexpiry + passport.MRPexpirycd + passport.MRPoptional + passport.MRPoptionalcd)

		kmrz= passport.MRPnumber + passport.MRPnumbercd + passport.MRPdob + passport.MRPdobcd + passport.MRPexpiry + passport.MRPexpirycd

		print
		print 'Generate local keys:'
		print
		if not TEST:
			print 'Supplied MRZ:  ' + arg0
			print 'Corrected MRZ: ' + passport.MRPnumber + passport.MRPnumbercd + passport.MRPnationality + passport.MRPdob + passport.MRPdobcd + passport.MRPsex + passport.MRPexpiry + passport.MRPexpirycd + passport.MRPoptional + passport.MRPoptionalcd+passport.MRPcompsoitecd
		print 'Key MRZ Info (kmrz): ' + kmrz
		print
		kseedhash= SHA.new(kmrz)
		kseed= kseedhash.digest()[:16]
		if DEBUG:
			print 'Kseed (SHA1 hash digest of kmrz): ' + kseedhash.hexdigest()[:32]

		# calculate Kenc & Kmac
		Kenc= passport.DESKey(kseed,passport.KENC,16)
		if DEBUG:
			print 'Kenc: ',
			passport.HexPrint(Kenc)
		Kmac= passport.DESKey(kseed,passport.KMAC,16)
		if DEBUG:
			print 'Kmac: ',
			passport.HexPrint(Kmac)
			print

		if TEST:
			rnd_ifd= TEST_rnd_ifd
			rnd_icc= TEST_rnd_icc
			Kifd= TEST_Kifd
		else:
			if DEBUG:
				print 'Get Challenge from Passport (rnd_icc): ',
			if passport.iso_7816_get_challenge(8):
				rnd_icc= passport.data
			else:
				passport.iso_7816_fail(passport.errorcode)	
			if DEBUG:
				passport.HexPrint(rnd_icc)
			rnd_ifd= passport.GetRandom(8)
			Kifd= passport.GetRandom(16)

		if DEBUG or TEST:
			print 'Generate local random Challenge (rnd_ifd): ' + rnd_ifd
			print 'Generate local random Challenge (Kifd): ' + Kifd
			print

		S= passport.ToBinary(rnd_ifd + rnd_icc + Kifd)

		if DEBUG or TEST:
			print 'S: ',
			passport.HexPrint(S)

		if DEBUG or TEST:
			print 'Kenc: ',
			passport.HexPrint(Kenc)


		tdes= DES3.new(Kenc,DES.MODE_CBC,passport.DES_IV)
		Eifd= tdes.encrypt(S)
		if DEBUG or TEST:
			print 'Eifd: ',
			passport.HexPrint(Eifd)
			print 'Kmac: ',
			passport.HexPrint(Kmac)
		Mifd= passport.DESMAC(Eifd,Kmac,'')
		if DEBUG or TEST:
			print 'Mifd: ',
			passport.HexPrint(Mifd)

		cmd_data= Eifd + Mifd
		if DEBUG or TEST:
			print 'cmd_data: ',
			passport.HexPrint(cmd_data)
			print

		if TEST:
			respdata= TEST_respdata
		else:
			print 'Authenticating: ',
			if passport.iso_7816_external_authenticate(passport.ToHex(cmd_data),Kmac):
				respdata= passport.data
			else:
				# failures allowed if we're brute forcing
				if brnum:
					respdata= ''
				else:
					passport.iso_7816_fail(passport.errorcode)
		if DEBUG or TEST:
			print 'Auth Response: ' + respdata
		resp= respdata[:64]
		respmac= respdata[64:80]
		if DEBUG or TEST:
			print 'Auth message: ' + resp
			print 'Auth MAC: ' + respmac + ' (verified)'
		decresp= passport.ToHex(tdes.decrypt(passport.ToBinary(resp)))
		if DEBUG or TEST:
			print 'Decrypted Auth Response: ' + decresp
			print 'Decrypted rnd_icc: ' + decresp[:16]
		recifd= decresp[16:32]
		if DEBUG or TEST:
			print 'Decrypted rnd_ifd: ' + recifd,
		# check returned rnd_ifd matches our challenge
		if not passport.ToBinary(recifd) == passport.ToBinary(rnd_ifd):
			print 'Challenge failed!'
			print 'Expected rnd_ifd: ', rnd_ifd
			print 'Received rnd_ifd: ', recifd
			if not bruteforce or iterations == 0:
				os._exit(True)
                        if bruteforcereset:
                                while not passport.hsselect('08', cardtype):
                                        print 'Waiting for passport... (%s)' % passport.errorcode
                                passport.iso_7816_select_file(passport.AID_MRTD,passport.ISO_7816_SELECT_BY_NAME,'0C')
		else:
			if DEBUG or TEST:
				print '(verified)'
			# challenge succeeded, so break
			break

	kicc= decresp[32:64] 
	if DEBUG or TEST:
		print 'Decrypted Kicc: ' + kicc

	# generate session keys
	print
	print 'Generate session keys: '
	print
	kseedhex= "%032x" % xor(int(Kifd,16),int(kicc,16))
	kseed= passport.ToBinary(kseedhex)
	print 'Kifd XOR Kicc (kseed): ',
	passport.HexPrint(kseed)
	KSenc= passport.DESKey(kseed,passport.KENC,16)
	print 'Session Key ENC: ',
	passport.HexPrint(KSenc)
	KSmac= passport.DESKey(kseed,passport.KMAC,16)
	print 'Session Key MAC: ',
	passport.HexPrint(KSmac)

	print
	# calculate Send Sequence Counter
	print 'Calculate Send Sequence Counter: '
	print
	SSC= passport.ToBinary(rnd_icc[8:16] + rnd_ifd[8:16])
	print 'SSC: ',
	passport.HexPrint(SSC)

	# secure select master file
	if TEST:
		KSmac= passport.ToBinary('F1CB1F1FB5ADF208806B89DC579DC1F8')
		rapdu= '990290008E08FA855A5D4C50A8ED9000'
		# ran out of steam on testing here! 
		os._exit(False)
	else:
		status, data= secure_read_file(KSenc,KSmac,TAG_FID[EF_COM])
		if not status:
			passport.iso_7816_fail(data)	

	# secure read file header
	#if TEST:
	#	KSmac= passport.ToBinary('F1CB1F1FB5ADF208806B89DC579DC1F8')
	#	rapdu= '8709019FF0EC34F9922651990290008E08AD55CC17140B2DED9000'
	#else:
	#	readlen= 4
	#	rapdu= secure_read_binary(KSmac,readlen,0)

	print 'EF.COM: ',
	if DEBUG:
		passport.HexPrint(data)
	eflist= decode_ef_com(data)
	raw_efcom= data
	efcom= open(tempfiles+TAG_FILE[EF_COM],'wb+')
	efcom.write(data)
	efcom.flush()
	efcom.close()
	print 'EF.COM stored in', tempfiles+TAG_FILE[EF_COM]

if not FILES and not BAC:
	status, data= read_file(TAG_FID[EF_COM])
	if not status:
		passport.iso_7816_fail(passport.errorcode)

	print 'EF.COM: ',
	if DEBUG:
		passport.HexPrint(data)
	eflist= decode_ef_com(data)
	raw_efcom= data
	bacfile= open(tempfiles+NOBAC_FILE,'wb+')
	bacfile.close()
	efcom= open(tempfiles+TAG_FILE[EF_COM],'wb+')
	efcom.write(data)
	efcom.flush()
	efcom.close()
	print 'EF.COM stored in', tempfiles+TAG_FILE[EF_COM]

# get SOD
#print
#print 'Select EF.SOD: ',
#data= secure_read_file(KSenc,KSmac,TAG_FID[EF_SOD])
#if DEBUG:
#	passport.HexPrint(data)
#sod= open(tempfiles+TAG_FILE[EF_SOD],'w+')
#sod.write(data)
#sod.flush()
#sod.close()
#print 'EF.SOD stored in', tempfiles+TAG_FILE[EF_SOD]

# Add Security Object and Main Directory to list for reading
eflist.insert(0,EF_SOD)
eflist.insert(0,EF_COM)
# now get everything else
for tag in eflist:
	print 'Reading:', TAG_NAME[tag]
	if not FILES:
		if BAC:
			status, data= secure_read_file(KSenc,KSmac,TAG_FID[tag])
		else:
			status, data= read_file(TAG_FID[tag])
		if not status:
			print "skipping (%s)" % passport.ISO7816ErrorCodes[data] 
			continue
	else:
		try:
			passfile= open(filespath+TAG_FILE[tag],'rb')
		except:
			print "*** Warning! Can't open %s" % filespath+TAG_FILE[tag]
			continue
		data= passfile.read()
	
	if DEBUG:
		passport.HexPrint(data)
	outfile= open(tempfiles+TAG_FILE[tag],'wb+')
	outfile.write(data)
	outfile.flush()
	outfile.close()
	print '  Stored in', tempfiles+TAG_FILE[tag]
	# special cases
	if tag == EF_SOD:
		# extract DER file (should be at offset 4 - if not, use sod.py to find it in EF_SOD.BIN
		# temporary evil hack until I have time to decode EF.SOD properly
		outfile= open(tempfiles+"EF_SOD.TMP",'wb+')
		outfile.write(data[4:])
		outfile.flush()
		outfile.close()
		exitstatus= os.system("openssl pkcs7 -text -print_certs -in %sEF_SOD.TMP -inform DER" % tempfiles)
		if not exitstatus:
			exitstatus= os.system("openssl pkcs7 -in %sEF_SOD.TMP -out %sEF_SOD.PEM -inform DER" % (tempfiles,tempfiles))
			exitstatus= os.system("openssl pkcs7 -text -print_certs -in %sEF_SOD.PEM" % tempfiles)
			print 
			print 'Certificate stored in %sEF_SOD.PEM' % tempfiles
	if tag == EF_DG1:
		mrz= decode_ef_dg1(data)
	if tag == EF_DG2:
		dg2_features= decode_ef_dg2(data)
	if tag == EF_DG7:
		decode_ef_dg7(data)

#initialise app if we are going to WRITE JMRTD
if Jmrtd:
	if not FILES:
		filespath=tempfiles
		print
		raw_input('Please replace passport with a JMRTD or vonJeek emulator card and press ENTER when ready...')
	if (not passport.hsselect('08', 'A') and not passport.hsselect('08', 'B')) or not passport.iso_7816_select_file(passport.AID_MRTD,passport.ISO_7816_SELECT_BY_NAME,'0C'):
		print "Couldn't select JMRTD!"
		os._exit(True)
	print "Initialising JMRTD or vonJeek..."
	if STRIP_INDEX:
		print 'Stripping AA & EAC files'
		print 'old EF.COM: '+raw_efcom.encode('hex')
		# DG.COM tag & length
		total_length= ord(raw_efcom[1])
		new_total_length= ord(raw_efcom[1])
		i= 2
		tmp= ''
		while i-2 < total_length-1:
			# next tag
			tag= raw_efcom[i]
			tmp+= raw_efcom[i]
			# not sure how to distinguish 2-byte tags...
			if raw_efcom[i]==chr(0x5F) or  raw_efcom[i]==chr(0x7F):
				i+= 1
				tag+= raw_efcom[i]
				tmp+= raw_efcom[i]
			i+= 1
			length= ord(raw_efcom[i])
			i+= 1
			if tag=='5C'.decode('hex'):
				# Keeping only known files in the tag index
				oldindex=raw_efcom[i:i+length]
				clearDGs=[chr(0x61), chr(0x75), chr(0x67), chr(0x6b), chr(0x6c), chr(0x6d), chr(0x63)]
				newindex=''.join(filter(lambda x: x in clearDGs, list(oldindex)))
				newlength=len(newindex)
				tmp+= chr(newlength)+newindex
				i+= newlength
				# Fixing total length:
				new_total_length= total_length-(length-newlength)
			else:
				tmp+= chr(length)+raw_efcom[i:i+length]
			i+= length
		raw_efcom= raw_efcom[0]+chr(new_total_length)+tmp
		print 'new EF.COM: '+raw_efcom.encode('hex')
		eflist= decode_ef_com(raw_efcom)
		eflist.insert(0,EF_SOD)
		eflist.insert(0,EF_COM)
	for tag in eflist:
		print 'Reading:', TAG_NAME[tag]
		if tag == EF_COM and STRIP_INDEX:
			data= raw_efcom
		else:
			try:
				passfile= open(filespath+TAG_FILE[tag],'rb')
			except:
				print "*** Warning! Can't open %s" % filespath+TAG_FILE[tag]
				continue
			data= passfile.read()
		print "Creating JMRTD", TAG_NAME[tag], "Length", len(data)
		jmrtd_create_file(TAG_FID[tag],len(data))
		print "Writing JMRTD", TAG_NAME[tag]
		jmrtd_write_file(TAG_FID[tag],data)
	# set private key
	# second line of MRZ is second half of decoded mrz from DG1
	passport.MRPmrzl(mrz[len(mrz) / 2:])
	print "Setting 3DES key"
	jmrtd_personalise(mrz[FieldKeys[0]:FieldKeys[0]+9],mrz[FieldKeys[1]:FieldKeys[1]+6],mrz[FieldKeys[2]:FieldKeys[2]+6])
	print "JMRTD/vonJeek 3DES key set to: " + mrz[FieldKeys[0]:FieldKeys[0]+9] + mrz[FieldKeys[1]:FieldKeys[1]+6] + mrz[FieldKeys[2]:FieldKeys[2]+6]
if JmrtdLock:
	jmrtd_lock()

# image read is nasty hacky bodge to see if image display without interpreting the headers
# start of image location may change - look for JPEG header bytes 'FF D8 FF E0'
# german is JP2 format, not JPG - look for '00 00 00 0C 6A 50'
# in /tmp/EF_DG2.BIN

def do_command(func, *args, **kw):
	def _wrapper(*wargs):
		return func(*(wargs + args), **kw)
	return _wrapper

# display data and image in gui window
Style= 'Arrow'
if not Nogui:
	root = Tk()

	font= 'fixed 22'
	fonta= 'fixed 22'

	frame = Frame(root, colormap="new", visual='truecolor').grid()
	root.title('%s (RFIDIOt v%s)' % (myver,passport.VERSION))
	if Filetype == "JP2":
		# nasty hack to deal with JPEG 2000 until PIL support comes along
		exitstatus= os.system("convert %sJP2 %sJPG" % (tempfiles+'EF_DG2.',tempfiles+'EF_DG2.'))
		print "      (converted %sJP2 to %sJPG for display)" % (tempfiles+'EF_DG2.',tempfiles+'EF_DG2.')
		if exitstatus:
			print 'Could not convert JPEG 2000 image (%d) - please install ImageMagick' % exitstatus
			os._exit(True)
		elif Display_DG7:
			os.system("convert %sJP2 %sJPG" % (tempfiles+'EF_DG7.',tempfiles+'EF_DG7.'))
			print "      (converted %sJP2 to %sJPG for display)" % (tempfiles+'EF_DG7.',tempfiles+'EF_DG7.')
		Filetype= 'JPG'
	imagedata = ImageTk.PhotoImage(file=tempfiles + 'EF_DG2.' + Filetype)
	canvas= Canvas(frame, height= imagedata.height(), width= imagedata.width())
	canvas.grid(row= 3, sticky= NW, rowspan= 20)
	canvasimage= canvas.create_image(0,0,image=imagedata, anchor=NW)
	featurebutton= Checkbutton(frame, text="Show Features", command=do_command(drawfeatures,canvas,dg2_features))
	featurebutton.grid(row= 1, column=0, sticky= W, rowspan= 1)
	featurestyle= Radiobutton(frame, text="Arrow",command=do_command(changestyle,"Arrow",canvas,dg2_features))
	featurestyle.grid(row= 1, column=0, rowspan= 1)
	featurestyle.select()
	featurestyle2= Radiobutton(frame, text="Cross",command=do_command(changestyle,"Cross",canvas,dg2_features))
	featurestyle2.grid(row= 2, column=0, rowspan= 1)
	featurestyle2.deselect()
	featurestyle3= Radiobutton(frame, text="Circle ",command=do_command(changestyle,"Circle",canvas,dg2_features))
	featurestyle3.grid(row= 1, column=0, rowspan= 1, sticky= E)
	featurestyle3.deselect()
	featurestyle4= Radiobutton(frame, text="Target",command=do_command(changestyle,"Target",canvas,dg2_features))
	featurestyle4.grid(row= 2, column=0, rowspan= 1, sticky= E)
	featurestyle4.deselect()
	quitbutton= Button(frame, text="Quit", command=root.quit)
	quitbutton.grid(row= 1, column=3, sticky= NE, rowspan= 2)
	Label(frame, text='Type').grid(row= 1, sticky= W, column= 1)
	Label(frame, text=DOCUMENT_TYPE[DocumentType], font= font).grid(row= 2, sticky= W, column= 1)
	row= 3
	for item in Fields:
		Label(frame, text=FieldNames[item]).grid(row= row, sticky= W, column= 1)
		row += 1
		mrzoffset= 0
		for x in range(item):
			mrzoffset += FieldLengths[x]
		if FieldNames[item] == "Issuing State or Organisation" or FieldNames[item] == "Nationality":
			Label(frame, text= mrzspaces(mrz[mrzoffset:mrzoffset + FieldLengths[item]],' ') + '  ' + passport.ISO3166CountryCodesAlpha[mrzspaces(mrz[mrzoffset:mrzoffset + FieldLengths[item]],'')], font= font).grid(row= row, sticky= W, column= 1)
		else:
			Label(frame, text=mrzspaces(mrz[mrzoffset:mrzoffset + FieldLengths[item]],' '), font= font).grid(row= row, sticky= W, column= 1)
		row += 1
	Label(frame, text='  ' + mrz[:len(mrz) / 2], font= fonta, justify= 'left').grid(row= row, sticky= W, columnspan= 4)
	row += 1
	Label(frame, text='  ' + mrz[len(mrz) / 2:], font= fonta, justify= 'left').grid(row= row, sticky= W, columnspan= 4)
	row += 1
	if Display_DG7:
		im = Image.open(tempfiles + 'EF_DG7.' + Filetype)
		width, height = im.size
		im=im.resize((300, 300 * height / width))
		pic=ImageTk.PhotoImage(im)
		width, height = im.size
		signcanvas= Canvas(frame, height= height, width= width)
		signcanvas.create_image(0,0,image=pic, anchor=NW)
		signcanvas.grid(row= row, sticky= NW, columnspan=4)
	row += 1
	Label(frame, text='http://rfidiot.org').grid(row= row, sticky= W, column= 1)
	root.mainloop()
passport.shutdown()
os._exit(False)
