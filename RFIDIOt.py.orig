#  RFIDIOt.py - RFID IO tools for python
# -*- coding: iso-8859-15 -*-
# 
#  Adam Laurie <adam@algroup.co.uk>
#  http://rfidiot.org/
# 
#  This code is copyright (c) Adam Laurie, 2006,7,8,9 All rights reserved.
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

# use Psyco compiler to speed things up if available
try:
	import psyco
	psyco.profile(0.01)
        psyco.full()
except ImportError:
        pass



import os
import sys
import random
import string
import time
from Crypto.Hash import SHA
from Crypto.Cipher import DES3
from Crypto.Cipher import DES
from operator import *
import pynfc
import signal


try:
	import smartcard, smartcard.CardRequest
	IOCTL_SMARTCARD_VENDOR_IFD_EXCHANGE = smartcard.scard.SCARD_CTL_CODE(1)
except:
	print '*** Warning - no pyscard installed or pcscd not running'

MASK_CCITT = 0x1021 # CRC-CCITT mask (ISO 3309, used in X25, HDLC)
MASK_11785 = 0x8408
MASK_CRC16 = 0xA001 # CRC16 mask (used in ARC files)

DEBUG= False
#DEBUG= True
NoInit= False
NFCReader= None

class rfidiot:
	"RFIDIOt - RFID I/O tools - http://rfidiot.org"
	# local imports
	from iso3166 import ISO3166CountryCodesAlpha
	from iso3166 import ISO3166CountryCodes
	#
	# open reader port
	#
	def __init__(self,readernum,reader,port,baud,to,debug,noinit,nfcreader):
		global NoInit
		global DEBUG
		self.readertype= reader
		self.readersubtype= reader
		readernum= int(readernum)
		DEBUG= debug
		NoInit= noinit
		NFCReader= nfcreader
		if not NoInit:
			if self.readertype == self.READER_PCSC:
				try:
					self.pcsc_protocol= smartcard.scard.SCARD_PROTOCOL_T1
				except:
					print 'Could not find PCSC daemon, try with option -n if you don\'t have a reader'
					os._exit(True)
				# select the reader specified
				try:
					self.pcsc= smartcard.System.readers()
				except:
					print 'Could not find PCSC daemon, try with option -n if you don\'t have a reader'
					os._exit(True)
				if readernum >= len(self.pcsc):
					print 'There is no such reader #%i, PCSC sees only %i reader(s)' % (readernum, len(self.pcsc))
					os._exit(True)
				try:
					self.readername= self.pcsc[readernum].name
					self.pcsc_connection= self.pcsc[readernum].createConnection()
					# debug option will show APDU traffic
					if DEBUG:
						from smartcard.CardConnectionObserver import ConsoleCardConnectionObserver
						observer=ConsoleCardConnectionObserver()
						self.pcsc_connection.addObserver( observer )
				except:
					print 'Could not create connection to %s' % self.readername
					os._exit(True)
				# determine PCSC subtype
				if string.find(self.readername,'OMNIKEY') == 0:
					self.readersubtype= self.READER_OMNIKEY
				else:
					if string.find(self.readername,'SDI010') == 0:
						self.readersubtype= self.READER_SCM
					else:
						if string.find(self.readername,'ACS ACR 38U') == 0 or string.find(self.readername,'ACS ACR38U') == 0:
							self.readersubtype= self.READER_ACS
							self.pcsc_protocol= smartcard.scard.SCARD_PROTOCOL_T0
							self.hcard = None
						elif string.find(self.readername,'ACS ACR122U PICC') == 0:
							self.readersubtype= self.READER_ACS
							self.pcsc_protocol= smartcard.scard.SCARD_PROTOCOL_T1
							self.hcard = None
						else:
							# default to Omnikey for now
							self.readersubtype= self.READER_OMNIKEY
				if DEBUG:
					print 'Reader Subtype:',self.readersubtype
				# create a connection
				try:
					self.pcsc_connection.connect()
				except:
					# card may be something like a HID PROX which only returns ATR and does not allow connect
					hresult, hcontext = smartcard.scard.SCardEstablishContext( smartcard.scard.SCARD_SCOPE_USER )
					if hresult != 0:
						raise error, 'Failed to establish context: ' + smartcard.scard.SCardGetErrorMessage(hresult)
					hresult, readers = smartcard.scard.SCardListReaders( hcontext, [] )
					readerstates= [ (readers[readernum], smartcard.scard.SCARD_STATE_UNAWARE ) ]
					hresult, newstates = smartcard.scard.SCardGetStatusChange( hcontext, 0, readerstates )
					if self.readersubtype == self.READER_ACS and self.pcsc_protocol == smartcard.scard.SCARD_PROTOCOL_T1:
						# SCARD_SHARE_SHARED if there is a PICC otherwise SCARD_SHARE_DIRECT
						hresult, hcard, dwActiveProtocol = smartcard.scard.SCardConnect(
							hcontext, readers[readernum], smartcard.scard.SCARD_SHARE_DIRECT, smartcard.scard.SCARD_PROTOCOL_T0 )
						self.hcard = hcard
						# Let's test if we can really use SCardControl, e.g. by sending a get_firmware_version APDU
						apdu = [ 0xFF, 0x00, 0x48, 0x00, 0x00 ]
						hresult, response = smartcard.scard.SCardControl( self.hcard, IOCTL_SMARTCARD_VENDOR_IFD_EXCHANGE, apdu )
						if hresult != smartcard.scard.SCARD_S_SUCCESS:
							print 'Failed to control: ' + smartcard.scard.SCardGetErrorMessage(hresult)
							if hresult == smartcard.scard.SCARD_E_NOT_TRANSACTED:
								print 'Did you set DRIVER_OPTION_CCID_EXCHANGE_AUTHORIZED in ifdDriverOptions in libccid_Info.plist?'
							os._exit(True)
					self.pcsc_atr= self.ListToHex(newstates[0][2])
					pass
				if self.readersubtype == self.READER_ACS:
					self.acs_set_retry(to)
			#libnfc device
			elif self.readertype == self.READER_LIBNFC:
				self.nfc = pynfc.NFC()
				self.readername = self.nfc.LIBNFC_READER
			elif self.readertype == self.READER_NONE:
				self.readername = 'none'
			else:	
				# frosch always starts at 9600 baud - need to add code to test for selected rate and
				# switch if required. 
				try:
					import serial
					self.ser = serial.Serial(port, baud, timeout=to)
					self.ser.readline()
					self.ser.flushInput()
					self.ser.flushOutput()
				except:
					print 'Could not open serial port %s' % port
					os._exit(True)
	#
	# variables
	#
	# VERSION: RFIDIOt.py version number
	# errorcode: 1 letter errorcode returned by the reader
	#
	# MIFAREdata: ASCII HEX representation of data block after successful read
	# MIFAREbinary: data block converted back to binary
	# MIFAREBLOCKLEN: constant ASCII HEX block length
	# MIFAREVALUELEN: constant ASCII HEX value length
	# MIFAREserialnumber: Unique ID (UID) of card
	# MIFAREkeyA: KEYA from key block (will always be 000000000000)
	# MIFAREkeyB: KEYB from key block
	# MIFAREaccessconditions: access conditions field from Key Block
	# MIFAREC1: Access conditions bitfield C1
	# MIFAREC2: Access conditions bitfield C2
	# MIFAREC3: Access conditions bitfield C3
	# MIFAREblock0AC: Block 0 Access Conditions
	# MIFAREblock1AC: Block 1 Access Conditions
	# MIFAREblock2AC: Block 2 Access Conditions
	# MIFAREblock3AC: Block 3 Access Conditions
	# MIFAREACKB: Human readable Key Block Access Conditions
	# MIFAREACDB: Human readable Data Block Access ConditionsA
	#
	# MRPmrzu: Machine Readable Passport - Machine Readable Zone - Upper
	# MRPmrzl Machine Readable Passport - Machine Readable Zone - Lower
	VERSION= '1.0c-beta'
	# Reader types
	READER_ACG= 0x01
	READER_FROSCH= 0x02
	READER_DEMOTAG= 0x03
	READER_PCSC= 0x04
	READER_OMNIKEY= 0x05
	READER_SCM= 0x06
	READER_ACS= 0x07
	READER_LIBNFC = 0x08
	READER_NONE = 0x09
	# TAG related globals
	errorcode= ''
	binary= ''
	data= ''
	sel_res= ''
	sens_res= ''
	tagtype= ''
	speed= ''
	framesize= ''
	uid= ''
	MIFAREdata=''
	MIFAREbinary=''
	MIFAREBLOCKLEN=32
	MIFAREVALUELEN=8
	MIFAREserialnumber= ''
	MIFAREcheckbyte= ''
	MIFAREmanufacturerdata= ''
	MIFAREkeyA= ''
	MIFAREkeyB= ''
	MIFAREaccessconditions= ''
	MIFAREaccessconditionsuserbyte= ' '
	MIFAREC1= 0
	MIFAREC2= 0
	MIFAREC3= 0
	MIFAREblock0AC= ''
	MIFAREblock1AC= ''
	MIFAREblock2AC= ''
	MIFAREblock3AC= ''
	# PCSC uses 'External Authentication', whereby keys are stored in the reader and then presented to the card. They only need
	# to be set up once per session, so login will store them in a global dictionary.
	# PCSC_Keys= { key : keynum } where keynum is 0 - 31 as per OmniKey docs
	PCSC_Keys= {}
	# Static Globals
	MIFAREACKB= {'000':'Write KeyA: KEYA, Read Access bits: KEYA, Write Access bits: NONE, Read KeyB: KEYA, Write KeyB: KEYA (KEYB readable)',\
		     '010':'Write KeyA: NONE, Read Access bits: KEYA, Write Access bits: NONE, Read KeyB: KEYA, Write KeyB: NONE (KEYB readable)',\
		     '100':'Write KeyA: KEYB, Read Access bits: KEYA/B, Write Access bits: NONE, Read KeyB: NONE, Write KeyB: KEYB',\
		     '110':'Write KeyA: NONE, Read Access bits: KEYA/B, Write Access bits: NONE, Read KeyB: NONE, Write KeyB: NONE',\
		     '001':'Write KeyA: KEYA, Read Access bits: KEYA, Write Access bits: KEYA, Read KeyB: KEYA, Write KeyB: KEYA (KEYB readable, transport configuration)',\
		     '011':'Write KeyA: KEYB, Read Access bits: KEYA/B, Write Access bits: KEYB, Read KeyB: NONE, Write KeyB: KEYB',\
		     '101':'Write KeyA: NONE, Read Access bits: KEYA/B, Write Access bits: KEYB, Read KeyB: NONE, Write KeyB: NONE',\
		     '111':'Write KeyA: NONE, Read Access bits: KEYA/B, Write Access bits: NONE, Read KeyB: NONE, Write KeyB: NONE'}
	MIFAREACDB= {'000':'Read: KEYA/B, Write: KEYA/B, Increment: KEYA/B, Decrement/Transfer/Restore: KEYA/B (transport configuration)',\
		     '010':'Read: KEYA/B, Write: NONE, Increment: NONE, Decrement/Transfer/Restore: NONE',\
		     '100':'Read: KEYA/B, Write: KEYB, Increment: NONE, Decrement/Transfer/Restore: NONE',\
		     '110':'Read: KEYA/B, Write: KEYB, Increment: KEYB, Decrement/Transfer/Restore: KEYA/B',\
		     '001':'Read: KEYA/B, Write: NONE, Increment: NONE, Decrement/Transfer/Restore: KEYA/B',\
		     '011':'Read: KEYB, Write: KEYB, Increment: NONE, Decrement/Transfer/Restore: NONE',\
		     '101':'Read: KEYB, Write: NONE, Increment: NONE, Decrement/Transfer/Restore: NONE',\
		     '111':'Read: NONE, Write: NONE, Increment: NONE, Decrement/Transfer/Restore: NONE'}
	LFXTags= {'U':'EM 4x02 (Unique)',\
		  'Z':'EM 4x05 (ISO FDX-B)',\
		  'T':'EM 4x50',\
		  'h':'Hitag 1 / Hitag S',\
		  'H':'Hitag 2',\
		  'Q':'Q5',\
		  'R':'TI-RFID Systems',\
		  'N':'No TAG present!'}
	# number of data blocks for each tag type (including block 0)
	LFXTagBlocks= {'U':0,\
		  'Z':0,\
		  'T':34,\
		  'h':64,\
		  'H':8,\
		  'Q':8,\
		  'R':18,\
		  'N':0}
	ALL= 'all'
	EM4x02= 'U'
	EM4x05= 'Z'
	Q5= 'Q'
	HITAG1= 'h'
	HITAG2= 'H'
	HITAG2_TRANSPORT_RWD='4D494B52'
	HITAG2_TRANSPORT_TAG='AA4854'
	HITAG2_TRANSPORT_HIGH='4F4E'
	HITAG2_PUBLIC_A= '02'
	HITAG2_PUBLIC_B= '00'
	HITAG2_PUBLIC_C= '04'
	HITAG2_PASSWORD= '06'
	HITAG2_CRYPTO= '0e'
	ACG_FAIL= 'N'
	# Mifare transort keys
	MIFARE_TK= { 'AA' : 'A0A1A2A3A4A5',\
		     'BB' : 'B0B1B2B3B4B5',\
		     'FF' : 'FFFFFFFFFFFF'}
	ISOTags= {'a':'ISO 14443 Type A  ',\
		  'b':'ISO 14443 Type B  ',\
		  'd':'ICODE UID         ',\
		  'e':'ICODE EPC         ',\
		  'i':'ICODE             ',\
		  's':'SR176             ',\
		  'v':'ISO 15693         '}
	ISOTagsA= {'t':'All Supported Tags'}
	ISO15693= 'v'
	# Manufacturer codes (Listed in ISO/IEC 7816-6)
	ISO7816Manufacturer= { '00':'Not Specified',\
			       '01':'Motorola',\
			       '02':'ST Microelectronics',\
			       '03':'Hitachi, Ltd',\
			       '04':'Philips Semiconductors (NXP)',\
			       '05':'Infineon Technologies AG',\
			       '06':'Cylinc',\
			       '07':'Texas Instrument',\
			       '08':'Fujitsu Limited',\
			       '09':'Matsushita Electronics Corporation',\
			       '0a':'NEC',\
			       '0b':'Oki Electric Industry Co. Ltd',\
			       '0c':'Toshiba Corp.',\
			       '0d':'Mitsubishi Electric Corp.',\
			       '0e':'Samsung Electronics Co. Ltd',\
			       '0f':'Hyundai Electronics Industries Co. Ltd',\
			       '10':'LG-Semiconductors Co. Ltd',\
			       '12':'HID Corporation',\
			       '16':'EM Microelectronic-Marin SA',
			       }
	ISOAPDU=  {'ERASE BINARY':'0E',
		   'VERIFY':'20',
		   # Global Platform
		   'INITIALIZE_UPDATE':'50',
		   # GP end
                   'MANAGE_CHANNEL':'70',
                   'EXTERNAL_AUTHENTICATE':'82',
                   'GET_CHALLENGE':'84',
                   'INTERNAL_AUTHENTICATE':'88',
                   'SELECT_FILE':'A4',
                   #vonjeek start
                   'VONJEEK_SELECT_FILE':'A5',
                   'VONJEEK_UPDATE_BINARY':'A6',
                   'VONJEEK_SET_MRZ':'A7',
		   'VONJEEK_SET_BAC':'A8',
		   'VONJEEK_SET_DATASET':'AA',
                   #vonjeek end
		   # special for JCOP
		   'MIFARE_ACCESS':'AA',
		   'ATR_HIST':'AB',
		   'SET_RANDOM_UID':'AC',
		   # JCOP end
                   'READ_BINARY':'B0',
                   'READ_RECORD(S)':'B2',
                   'GET_RESPONSE':'C0',
                   'ENVELOPE':'C2',
                   'GET_DATA':'CA',
                   'WRITE_BINARY':'D0',
                   'WRITE_RECORD':'D2',
                   'UPDATE_BINARY':'D6',
                   'PUT_DATA':'DA',
                   'UPDATE_DATA':'DC',
		   'CREATE_FILE':'E0',
                   'APPEND_RECORD':'E2',
		   # Global Platform
		   'GET_STATUS':'F2',
		   # GP end
		   'READ_BALANCE':'4C',
		   'INIT_LOAD': '40',
		   'LOAD_CMD':'42',
		   'WRITE_MEMORY':'7A',
		   'READ_MEMORY':'78',
		   }
	# some control parameters
	ISO_7816_SELECT_BY_NAME= '04'
	ISO_7816_SELECT_BY_EF= '02'
	ISO_7816_OPTION_FIRST_OR_ONLY= '00'
	ISO_7816_OPTION_NEXT_OCCURRENCE= '02'

	# well known AIDs
	AID_CARD_MANAGER= 'A000000003000000'
	AID_MRTD= 'A0000002471001'
	AID_JAVA_LANG= 'A0000000620001'
	AID_JAVACARD_FRAMEWORK= 'A0000000620101'
	AID_JAVACARD_SECURITY= 'A0000000620102'
	AID_JAVARCARDX_CRYPTO= 'A0000000620201'
	AID_FIPS_140_2= 'A000000167413001'
	AID_JAVACARD_BIOMETRY= 'A0000001320001'
	AID_SECURITY_DOMAIN= 'A0000000035350'
	AID_PKCS_15= 'A000000063'
	AID_JCOP_IDENTIFY= 'A000000167413000FF'

	# Global Platform
	CLA_GLOBAL_PLATFORM= '80'
	GP_MAC_KEY= '404142434445464748494A4B4C4D4E4F'
	GP_ENC_KEY= '404142434445464748494A4B4C4D4E4F'
	GP_KEK_KEY= '404142434445464748494A4B4C4D4E4F'
	GP_NO_ENCRYPTION= '00'
	GP_C_MAC= '01'
	GP_C_MAC_DECRYPTION= '02'
	GP_SCP02= '02'
	GP_REG_DATA= 'E3'
	GP_REG_AID= '4F'
	GP_REG_LCS= '9F70'
	GP_REG_PRIV= 'C5'
	GP_FILTER_ISD= '80'
	GP_FILTER_ASSD= '40'
	GP_FILTER_ELF= '20'

	ISO_OK= '9000'
	ISO_SECURE= '6982'
	ISO_NOINFO= '6200'

	ISO_SPEED= {'00':'106kBaud',\
		    '02':'212kBaud',\
		    '04':'424kBaud',\
		    '08':'848kBaud'}
	ISO_FRAMESIZE= { '00':'16',\
			 '01':'24',\
			 '02':'32',\
			 '03':'40',\
			 '04':'48',\
			 '05':'64',\
			 '06':'96',\
			 '07':'128',\
			 '08':'256'}
	ISO7816ErrorCodes=  {
			    '61':'SW2 indicates the number of response bytes still available',
			    '6200':'No information given',
			    '6281':'Part of returned data may be corrupted',
			    '6282':'End of file/record reached before reading Le bytes',
			    '6283':'Selected file invalidated',
			    '6284':'FCI not formatted according to ISO7816-4 section 5.1.5',
			    '6300':'No information given',
			    '6301':'ACR: PN532 does not respond',
			    '6327':'ACR: Contacless Response invalid checksum',
			    '637F':'ACR: PN532 invalid Contactless Command',
			    '6381':'File filled up by the last write',
			    '6382':'Card Key not supported',
			    '6383':'Reader Key not supported',
			    '6384':'Plain transmission not supported',
			    '6385':'Secured Transmission not supported',
			    '6386':'Volatile memory not available',
			    '6387':'Non Volatile memory not available',
			    '6388':'Key number not valid',
			    '6389':'Key length is not correct',
			    '63C':'Counter provided by X (valued from 0 to 15) (exact meaning depending on the command)',
			    '64':'State of non-volatile memory unchanged (SW2=00, other values are RFU)',
			    '6400':'Card Execution error',
			    '6500':'No information given',
			    '6581':'Memory failure',
			    '66':'Reserved for security-related issues (not defined in this part of ISO/IEC 7816)',
			    '6700':'Wrong length',
			    '6800':'No information given',
			    '6881':'Logical channel not supported',
			    '6882':'Secure messaging not supported',
			    '6900':'No information given',
			    '6981':'Command incompatible with file structure',
			    '6982':'Security status not satisfied',
			    '6983':'Authentication method blocked',
			    '6984':'Referenced data invalidated',
			    '6985':'Conditions of use not satisfied',
			    '6986':'Command not allowed (no current EF)',
			    '6987':'Expected SM data objects missing',
			    '6988':'SM data objects incorrect',
			    '6A00':'No information given',
			    '6A80':'Incorrect parameters in the data field',
			    '6A81':'Function not supported',
			    '6A82':'File not found',
			    '6A83':'Record not found',
			    '6A84':'Not enough memory space in the file',
			    '6A85':'Lc inconsistent with TLV structure',
			    '6A86':'Incorrect parameters P1-P2',
			    '6A87':'Lc inconsistent with P1-P2',
			    '6A88':'Referenced data not found',
			    '6B00':'Wrong parameter(s) P1-P2',
			    '6C':'Wrong length Le: SW2 indicates the exact length',
			    '6D00':'Instruction code not supported or invalid',
			    '6E00':'Class not supported',
			    '6F00':'No precise diagnosis',
			    '9000':'No further qualification',
			    'ABCD':'RFIDIOt: Reader does not support this command',
			    'F':'Read error or Security status not satisfied',
			    'FFFB':'Mifare (JCOP) Block Out Of Range',
			    'FFFF':'Unspecified Mifare (JCOP) Error',
			    'N':'No precise diagnosis',
			    'PC00':'No TAG present!',
			    'PC01':'PCSC Communications Error',
			    'PN00': 'PN531 Communications Error',
			    'R':'Block out of range',
			    'X':'Authentication failed',
			    }
	DES_IV='\0\0\0\0\0\0\0\0'
	DES_PAD= [chr(0x80),chr(0),chr(0),chr(0),chr(0),chr(0),chr(0),chr(0)]
	DES_PAD_HEX= '8000000000000000'
	KENC= '\0\0\0\1'
	KMAC= '\0\0\0\2'
	DO87= '870901'
	DO8E= '8E08'
	DO97= '9701'
	DO99= '99029000'
	#
	# frosch command set
	#
	#
	# Reader Key Init Mode (update internal secret key)
	FR_RWD_Key_Init_Mode= chr(0x4B)
	# Reader Key Init Mode Reset (exit key init mode)
	FR_RWD_KI_Reset= chr(0x52)
	# READER Key Init Mode Read EEPROM
	FR_RWD_KI_Read_EE_Data= chr(0x58)
	# Reader Stop
	FR_RWD_Stop_Cmd= chr(0xA6)
	# Reader Reset
	FR_RWD_HF_Reset= chr(0x68)
	# Reader Version
	FR_RWD_Get_Version= chr(0x56)
	# Hitag1 Get Serial Number
	FR_HT1_Get_Snr= chr(0x47)
	# Hitag1 Get Serial Number & set tag into Advanced Protocol Mode
	FR_HT1_Get_Snr_Adv= chr(0xA2)
	# Hitag1 Select Last Seen
	FR_HT1_Select_Last= chr(0x53)
	# Hitag1 Select Serial Number
	FR_HT1_Select_Snr= chr(0x53)
	# Hitag1 Read Page
	FR_HT1_Read_Page= chr(0x50)
	# Hitag2 Get Serial Number (password mode)
	FR_HT2_Get_Snr_PWD= chr(0x80) + chr(0x00)
	# Hitag2 Get Serial Number Reset (to reset for normal access when in public modes)
	FR_HT2_Get_Snr_Reset= chr(0x80)
	# Hitag2 Halt Selected
	FR_HT2_Halt_Selected= chr(0x81)
	# Hitag2 read page
	FR_HT2_Read_Page= chr(0x82)
	# Hitag2 Read Miro (Unique / Public Mode A)
	FR_HT2_Read_Miro= chr(0x4d)
	# Hitag2 Read Public B (FDX-B)
	FR_HT2_Read_PublicB= chr(0x9e)
	# Hitag2 Write Page
	FR_HT2_Write_Page= chr(0x84)
	#
	# frosch errors
	#
	FROSCH_Errors= { '00':'No Error',\
			 '02':'Error',\
			 '07':'No Error',\
			 'eb':'Antenna Overload',\
			 'f1':'EEPROM Read Protected',\
			 'f2':'EEPROM Write Protected',\
			 'f3':'EEPROM Wrong - Old Data',\
			 'f4':'EEPROM Error',\
			 'f5':'CryptoBlock not INIT',\
			 'f6':'Acknowledgement Error',\
			 'f9':'Authentication Error',\
			 'fa':'Incorrect Password TAG',\
			 'fb':'Incorrect Password RWD',\
			 'fc':'Timeout',\
			 'fd':'No TAG present!',\
			 'ff':'Serial port fail or wrong mode'}
	# 
	# frosch constants
	#
	FR_BAUD_RATE= {   9600:chr(0x01),\
		   	 14400:chr(0x02),\
		   	 19200:chr(0x03),\
		   	 38400:chr(0x04),\
		   	 57600:chr(0x05),\
		  	115200:chr(0x06)}
	FR_NO_ERROR= chr(0x00)
	FR_PLAIN= chr(0x00)
	FR_CRYPTO= chr(0x01)
	FR_TIMEOUT= 'fc'
	FR_COMMAND_MODE= 0x00
	FR_KEY_INIT_MODE= 0x01
	#
	# frosch statics
	#
	FR_BCC_Mode= FR_COMMAND_MODE
	#
	# DemoTag command set
	#
	DT_SET_UID= 'u'
	#
	# DemoTag Errors
	#
	DT_ERROR= '?'
	#
	# PCSC APDUs
	#
	# these are basically standard APDUs but with fields filled in and using OmniKey terminology
	# should really unify them all, but for now...
	# COMMAND : [Class, Ins, P1, P2, DATA, LEN]
	PCSC_APDU= {
		    'ACS_14443_A' : ['d4','40','01'],
		    'ACS_14443_B' : ['d4','42','02'],
		    'ACS_14443_0' : ['d5','86','80', '05'],
		    'ACS_DISABLE_AUTO_POLL' : ['ff','00','51','3f','00'],
		    'ACS_DIRECT_TRANSMIT' : ['ff','00','00','00'],
		    'ACS_GET_SAM_SERIAL' : ['80','14','00','00','08'],
		    'ACS_GET_SAM_ID' : ['80','14','04','00','06'],
		    'ACS_GET_READER_FIRMWARE' : ['ff','00','48','00','00'],
		    'ACS_GET_RESPONSE' : ['ff','c0','00','00'],
		    'ACS_GET_STATUS' : ['d4','04'],
		    'ACS_IN_LIST_PASSIVE_TARGET' : ['d4','4a'],
		    'ACS_LED_GREEN' : ['ff','00','40','0e','04','00','00','00','00'],
		    'ACS_LED_ORANGE' : ['ff','00','40','0f','04','00','00','00','00'],
		    'ACS_LED_RED' : ['ff','00','40','0d','04','00','00','00','00'],
		    'ACS_MIFARE_LOGIN' : ['d4','40','01'],
		    'ACS_READ_MIFARE' : ['d4','40','01','30'],
		    'ACS_POLL_MIFARE' : ['d4','4a','01','00'],
		    'ACS_POWER_OFF' : ['d4','32','01','00'],
		    'ACS_POWER_ON' : ['d4','32','01','01'],
		    'ACS_RATS_14443_4_OFF' : ['d4','12','24'],
		    'ACS_RATS_14443_4_ON' : ['d4','12','34'],
		    'ACS_SET_PARAMETERS' : ['d4','12'],
		    'ACS_SET_RETRY' : ['d4','32','05','00','00','00'],
		    'AUTHENTICATE' : ['ff', ISOAPDU['INTERNAL_AUTHENTICATE']],
		    'GUID' : ['ff', ISOAPDU['GET_DATA'], '00', '00', '00'],
		    'ACS_GET_ATS' : ['ff', ISOAPDU['GET_DATA'], '01', '00', '00'],
		    'LOAD_KEY' : ['ff',  ISOAPDU['EXTERNAL_AUTHENTICATE']],
		    'READ_BLOCK' : ['ff', ISOAPDU['READ_BINARY']],
		    'UPDATE_BLOCK' : ['ff', ISOAPDU['UPDATE_BINARY']],
		    'VERIFY' : ['ff', ISOAPDU['VERIFY']],
		    'WRITE_BLOCK' : ['ff', ISOAPDU['WRITE_BINARY']],
		    }
	# PCSC Errors
	PCSC_NO_CARD= 'PC00'
	PCSC_COMMS_ERROR= 'PC01'
	PCSC_VOLATILE= '00'
	PCSC_NON_VOLATILE= '20'
	# PCSC Contactless Storage Cards
	PCSC_CSC= '804F'
	# PCSC Workgroup RID
	PCSC_RID= 'A000000306'
	# PCSC Storage Standard Byte
	PCSC_SS= { '00':'No information given',\
		   '01':'ISO 14443 A, part 1',\
		   '02':'ISO 14443 A, part 2',\
		   '03':'ISO 14443 A, part 3',\
		   '04':'RFU',\
		   '05':'ISO 14443 B, part 1',\
		   '06':'ISO 14443 B, part 2',\
		   '07':'ISO 14443 B, part 3',\
		   '08':'RFU',\
		   '09':'ISO 15693, part 1',\
                   '0A':'ISO 15693, part 2',\
                   '0B':'ISO 15693, part 3',\
                   '0C':'ISO 15693, part 4',\
		   '0D':'Contact (7816-10) I2 C',\
		   '0E':'Contact (7816-10) Extended I2 C',\
		   '0F':'Contact (7816-10) 2WBP',\
		   '10':'Contact (7816-10) 3WBP',\
		   'FF':'RFU'}
	# PCSC card names
	PCSC_NAME= { '0000':'No name given',\
		     '0001':'Mifare Standard 1K',\
		     '0002':'Mifare Standard 4K',\
		     '0003':'Mifare Ultra light',\
		     '0004':'SLE55R_XXXX',\
		     '0006':'SR176',\
		     '0007':'SRI X4K',\
		     '0008':'AT88RF020',\
		     '0009':'AT88SC0204CRF',\
		     '000A':'AT88SC0808CRF',\
		     '000B':'AT88SC1616CRF',\
		     '000C':'AT88SC3216CRF',\
		     '000D':'AT88SC6416CRF',\
		     '000E':'SRF55V10P',\
		     '000F':'SRF55V02P',\
		     '0010':'SRF55V10S',\
		     '0011':'SRF55V02S',\
		     '0012':'TAG_IT',\
		     '0013':'LRI512',\
		     '0014':'ICODESLI',\
		     '0015':'TEMPSENS',\
		     '0016':'I.CODE1',\
		     '0017':'PicoPass 2K',\
		     '0018':'PicoPass 2KS',\
		     '0019':'PicoPass 16K',\
		     '001A':'PicoPass 16Ks',\
		     '001B':'PicoPass 16K(8x2)',\
		     '001C':'PicoPass 16KS(8x2)',\
		     '001D':'PicoPass 32KS(16+16)',\
		     '001E':'PicoPass 32KS(16+8x2)',\
		     '001F':'PicoPass 32KS(8x2+16)',\
		     '0020':'PicoPass 32KS(8x2+8x2)',\
		     '0021':'LRI64',\
		     '0022':'I.CODE UID',\
		     '0023':'I.CODE EPC',\
		     '0024':'LRI12',\
		     '0025':'LRI128',\
		     '0026':'Mifare Mini'}
	# ACS Constants
	ACS_TAG_FOUND= 'D54B'
	ACS_DATA_OK= 'D541'
	ACS_NO_SAM= '3B00'
	ACS_TAG_MIFARE_ULTRA= 'MIFARE Ultralight'
	ACS_TAG_MIFARE_1K= 'MIFARE 1K'
	ACS_TAG_MIFARE_MINI= 'MIFARE MINI'
	ACS_TAG_MIFARE_4K= 'MIFARE 4K'
	ACS_TAG_MIFARE_DESFIRE= 'MIFARE DESFIRE'
	ACS_TAG_JCOP30= 'JCOP30'
	ACS_TAG_JCOP40= 'JCOP40'
	ACS_TAG_MIFARE_OYSTER= 'London Transport Oyster'
	ACS_TAG_GEMPLUS_MPCOS= 'Gemplus MPCOS'

	ACS_TAG_TYPES=	{
			'00':ACS_TAG_MIFARE_ULTRA,
			'08':ACS_TAG_MIFARE_1K,
			'09':ACS_TAG_MIFARE_MINI,
			'18':ACS_TAG_MIFARE_4K,
			'20':ACS_TAG_MIFARE_DESFIRE,
			'28':ACS_TAG_JCOP30,
			'38':ACS_TAG_JCOP40,
			'88':ACS_TAG_MIFARE_OYSTER,
			'98':ACS_TAG_GEMPLUS_MPCOS,
			}
	# HID constants
	HID_PROX_H10301= '3B0601'
	HID_PROX_H10302= '3B0702'
	HID_PROX_H10304= '3B0704'
	HID_PROX_H10320= '3B0514'
	HID_PROX_CORP1K= '3B0764'
	HID_PROX_TYPES=	{
			HID_PROX_H10301:'HID Prox H10301 - 26 bit (FAC + CN)',
			HID_PROX_H10302:'HID Prox H10302 - 37 bit (CN)',
			HID_PROX_H10304:'HID Prox H10304 - 37 bit (FAC + CN)',
			HID_PROX_H10320:'HID Prox H10320 - 32 bit clock/data card',
			HID_PROX_CORP1K:'HID Prox Corp 1000 - 35 bit (CIC + CN)',
			}
	#
	# local/informational functions
	#
	def info(self,caller):
		if len(caller) > 0:
			print caller + ' (using RFIDIOt v' + self.VERSION + ')'
		if not NoInit:
			self.reset()
			self.version()
			if len(caller) > 0:
				print '  Reader:',
			if self.readertype == self.READER_ACG:
				print 'ACG ' + self.readername,
				print ' (serial no: ' + self.id() + ')'
			if self.readertype == self.READER_FROSCH:
				print 'Frosch ' + self.ToBinary(self.data[:16]) + ' / ' + self.ToBinary(self.data[16:32]),
				print ' (serial no: ' + self.data[32:54] + ')'
			if self.readertype == self.READER_PCSC:
				print 'PCSC ' + self.readername
				if self.readersubtype == self.READER_ACS and self.pcsc_protocol == smartcard.scard.SCARD_PROTOCOL_T0:
					# get ATR to see if we have a SAM
					self.select()
					if not self.pcsc_atr[:4] == self.ACS_NO_SAM:
						if self.acs_get_firmware_revision():
							print '          (Firmware: %s, ' % self.ToBinary(self.data),
						else:
							print "\ncan't get firmware revision!"
							os._exit(True)
						if self.acs_get_sam_serial():
							print 'SAM Serial: %s, ' % self.data,
						else:
							print "\ncan't get SAM Serial Number!"
							os._exit(True)
						if self.acs_get_sam_id():
							print 'SAM ID: %s)' % self.ToBinary(self.data)
						else:
							print "\ncan't get SAM Serial Number!"
							os._exit(True)
				elif self.readersubtype == self.READER_ACS and self.pcsc_protocol == smartcard.scard.SCARD_PROTOCOL_T1:
					if self.acs_get_firmware_revision():
						print '          (Firmware: %s)' % self.ToBinary(self.data)
					else:
						print "\ncan't get firmware revision!"
						os._exit(True)
			if self.readertype == self.READER_LIBNFC:			
				print 'LibNFC', self.readername
			print
	#
	# reader functions
	#
        def reset(self):
		if self.readertype == self.READER_ACG:
			# send a select to stop just in case it's in multi-select mode
			self.ser.write('s')
			self.ser.readline()
			self.ser.flushInput()
			self.ser.flushOutput()
			# now send a reset and read response
			self.ser.write('x')
			self.ser.readline()
			# now send a select and read remaining lines
			self.ser.write('s')
			self.ser.readline()
			self.ser.flushInput()
			self.ser.flushOutput()
			return True
		if self.readertype == self.READER_FROSCH:
			if self.frosch(self.FR_RWD_HF_Reset,''):
				return True
			else:
				print self.FROSCH_Errors[self.errorcode]
				os._exit(True)
		if self.readertype == self.READER_PCSC:
			if self.readersubtype == self.READER_ACS:
				self.acs_power_off()			
				self.acs_power_on()			
			self.data= 'A PCSC Reader (need to add reset function!)'
		if self.readertype == self.READER_LIBNFC:
			self.nfc.powerOff()
			self.nfc.powerOn()
	def version(self):
		if self.readertype == self.READER_ACG:
			self.ser.write('v')
			try:
				self.data= self.ser.readline()[:-2]
				self.readername= self.data
			except:
				print '\nReader not responding - check baud rate'
				os._exit(True)
			# check for garbage data (wrong baud rate)
			if not self.data or self.data[0] < ' ' or self.data[0] > '~':
				print '\nGarbage received from reader - check baud rate'
				os._exit(True)
			return True
		if self.readertype == self.READER_FROSCH:
			if self.frosch(self.FR_RWD_Get_Version,''):
				return True
			else:
				print self.FROSCH_Errors[self.errorcode]
				os._exit(True)
	def id(self):
		return self.readEEPROM(0)[:2] + self.readEEPROM(1)[:2] + self.readEEPROM(2)[:2] + self.readEEPROM(3)[:2]
	def station(self):
		return self.readEEPROM(0x0a)[:2]
	def PCON(self):
		return self.readEEPROM(0x0b)[:2]
	def PCON2(self):
		return self.readEEPROM(0x13)[:2]
	def PCON3(self):
		return self.readEEPROM(0x1b)[:2]
	def BAUD(self):
		return self.readEEPROM(0x0c)[:2]
	def CGT(self):
		return self.readEEPROM(0x0d)[:2]
	def opmode(self):
		return self.readEEPROM(0x0e)[:2]
	def SST(self):
		return self.readEEPROM(0x0f)[:2]
	def ROT(self):
		return self.readEEPROM(0x14)[:2]
	def RRT(self):
		return self.readEEPROM(0x15)[:2]
	def AFI(self):
		return self.readEEPROM(0x16)[:2]
	def STOa(self):
		return self.readEEPROM(0x17)[:2]
	def STOb(self):
		return self.readEEPROM(0x18)[:2]
	def STOs(self):
		return self.readEEPROM(0x19)[:2]
	def readEEPROM(self,byte):
		self.ser.write('rp%02x' % byte)
		return self.ser.readline()[:2]
	def writeEEPROM(self,byte,value):
		self.ser.write('wp%02x%02x' % (byte,value))
		self.errorcode= self.ser.readline()[:-2]
		if eval(self.errorcode) == value:
			return True
		return False
	def settagtype(self,type):
		if self.readertype == self.READER_ACG:
			# ACG HF reader uses 't' for 'all', LF uses 'a'
			if type == self.ALL:
				if string.find(self.readername,'LFX') == 0:
					type= 'a'
				else:
					type= 't'
			self.ser.write('o' + type)
			self.errorcode= self.ser.readline()[:-2]
			if self.errorcode == 'O' + string.upper(type):
				self.tagtype= type
				return True
		if self.readertype == self.READER_FROSCH:
			if type == self.EM4x02:
				return self.frosch(self.FR_HT2_Read_Miro,'')			
			if type == self.EM4x05:
				return self.frosch(self.FR_HT2_Read_PublicB,'')
		return False
	#
	# card functions
	#
	def pcsc_listreaders(self):
		n= 0
		print 'PCSC devices:'
		#for reader in self.pcsc.listReader():
		for reader in self.pcsc:
			print '    No: %d\t\t%s' % (n,reader)
			n += 1
	def libnfc_listreaders(self):
		self.nfc.listreaders(NFCReader)
	def waitfortag(self,message):
		print message
		# we need a way to interrupt infinite loop
		if self.readersubtype == self.READER_OMNIKEY or self.readersubtype == self.READER_SCM:
			wait=True
			while wait:
				try:
					self.pcsc_connection.connect()
					self.select()
					wait=False
				except:
					sys.stdin.flush()
					time.sleep(0.5)
		else:
			while not self.select():
				# do nothing
				time.sleep(0.1)
		return True
	def select(self):
		self.uid= ''
		# return True or False and set tag type and data
		if self.readertype == self.READER_ACG:
			self.ser.write('s')
			self.data= self.ser.readline()[:-2]
			self.tagtype= self.data[:1]
			if self.tagtype == self.ACG_FAIL:
				self.errorcode= self.PCSC_NO_CARD
				return False
			# strip leading tag type from LFX response
			if self.readername.find("LFX") == 0:
				self.uid= self.data[1:]
			else:
				self.uid= self.data
			return True
		if self.readertype == self.READER_FROSCH:
			if self.frosch(self.FR_HT2_Get_Snr_PWD,''):
				# select returns an extra byte on the serial number, so strip it
				self.data= self.data[:len(self.data) - 2]
				self.tagtype= self.HITAG2
				self.uid= self.data
				return True
			if self.frosch(self.FR_HT1_Get_Snr,''):
				# select returns an extra byte on the serial number, so strip it
				# and preserve for after select command
				serialno= self.data[:len(self.data) - 2]
				if self.frosch(self.FR_HT1_Select_Last,''):
					self.tagtype= self.HITAG1
					self.data= self.uid= serialno
					return True
			return False
		if self.readertype == self.READER_PCSC:
			try:
				# start a new connection in case TAG has been switched
				self.pcsc_connection.disconnect()
				self.pcsc_connection.connect()
				time.sleep(0.6)	
				self.pcsc_atr= self.ListToHex(self.pcsc_connection.getATR())
				atslen= 2 * int(self.pcsc_atr[3],16)
				self.pcsc_ats= self.pcsc_atr[8:8 + atslen]
				if self.readersubtype == self.READER_ACS:
					self.acs_select_tag()
				else:
					self.pcsc_send_apdu(self.PCSC_APDU['GUID'])
			except smartcard.Exceptions.NoCardException:
				self.errorcode= self.PCSC_NO_CARD
				return False
			except:
				self.errorcode= self.PCSC_COMMS_ERROR
				return False
			if self.errorcode == self.ISO_OK:
				self.uid= self.data
				if not self.readersubtype == self.READER_ACS:
					self.tagtype= self.PCSCGetTagType(self.pcsc_atr)
				# pcsc returns ISO15693 tags LSByte first, so reverse
				if string.find(self.tagtype,'ISO 15693') >= 0:
					self.data= self.uid= self.HexByteReverse(self.data)
				return True
			else:
				return False
		if self.readertype == self.READER_LIBNFC:
			try:
				if DEBUG:
					print 'reading card using LIBNFC'
				result = self.nfc.readISO14443A()
				if result:
					self.atr = result.atr
					self.uid = result.uid
					if DEBUG:
						print 'ATR: ' + self.atr
						print 'UID: ' + self.uid
					return True
				else:
					if DEBUG:
						print 'Error selecting card'
					return False
			except ValueError:
				self.errorcode = 'Error reading card using LIBNFC' + e
		return False
	def h2publicselect(self):
		"select Hitag2 from Public Mode A/B/C"
		if self.readertype == self.READER_FROSCH:
			if (self.frosch(self.FR_HT2_Get_Snr_Reset,self.FR_PLAIN + 'M')):
				self.tagtype= self.HITAG2
				self.data= self.data[:8]
				return True
		return False
	def h2login(self,password):
		"login to hitag2 in password mode"
		if not self.readertype == self.READER_ACG:
			print 'Reader type not supported for hitag2login!'
			return False
		self.ser.write('l'+password)
		ret= self.ser.readline()[:-2]
		if ret == self.ACG_FAIL:
			self.errorcode= ret
			return False
		return True
	def hsselect(self,speed):
		if self.readertype == self.READER_PCSC or self.readertype == self.READER_LIBNFC:
			# low level takes care of this, so normal select only
			if self.select():
				#fixme - find true speed/framesize
				self.speed= '04'
				self.framesize= '08'
				return True
			else:
				return False
		"high speed select - 106 (speed= 01), 212 (speed= 02), 424 (speed= 04) or 848 (speed= 08) kBaud"
		self.ser.write('h'+speed)
		ret= self.ser.readline()[:-2]
		if ret == self.ACG_FAIL:
			self.errorcode= ret
			return False
		sizebaud= ret[-2:]
		self.speed= '%02d' % int(sizebaud[-1:])
		self.framesize= '%02d' % int(sizebaud[:-1])
		self.data= ret[:-2]
		return True
	# ACS specific commands
	#
	# note there are 2 different types of ACS command:
	#   
	#    standard APDU for reader - acs_send_reader_apdu
	#    pseudo APDU for contact or contactless card - acs_send_apdu
	#	
	# contact and contacless commands are wrapped and passed to the NXP PN532 for processing
	def acs_send_apdu(self,apdu):
		"ACS send APDU to contacless card"
		myapdu= self.HexArraysToArray(apdu)
		# determine if this is for direct transmission to the card
		if myapdu[0] == 'd4':
			# build pseudo command for ACS contactless interface
			lc= '%02x' % len(myapdu)
			apduout= self.HexArrayToList(self.PCSC_APDU['ACS_DIRECT_TRANSMIT']+[lc]+myapdu)
		else:
			if  myapdu[0] == 'ff' or myapdu[0] == '80':
				apduout= self.HexArrayToList(myapdu)
			else:
				# build pseudo command for ACS 14443-A
				lc= '%02x' % (len(myapdu) + len(self.PCSC_APDU['ACS_14443_A']))
				apduout= self.HexArrayToList(self.PCSC_APDU['ACS_DIRECT_TRANSMIT']+[lc]+self.PCSC_APDU['ACS_14443_A']+myapdu)
		result, sw1, sw2= self.acs_transmit_apdu(apduout)
		self.errorcode= '%02X%02X' % (sw1,sw2)
		if self.errorcode == self.ISO_OK:
			self.data= self.ListToHex(result)
			if not myapdu[0] == 'ff' and not myapdu[0] == '80' and not myapdu[0] == 'd4':
				# this is a 14443-A command, so needs further processing
				# last 4 data bytes is status of wrapped command
				if self.data[-4:] == self.ISO_OK and len(self.data) > 6:
					# strip first 6 hex characters (ACS specific)
					self.data= self.data[6:]
					# strip last 4 to remove errorcode
					self.data= self.data[:-4]
					return True
				else:
					self.errorcode= self.data[-4:]
					# strip ACS status and errorcode in case there is some data expected despite error
					self.data= self.data[6:-4]
					return False
			return True
		self.data= ''
		return False
	def acs_transmit_apdu(self,apdu):
		"ACS send APDU and retrieve additional DATA if required"
		if self.hcard is None:
			result, sw1, sw2= self.pcsc_connection.transmit(apdu,protocol= self.pcsc_protocol)
			if sw1 == 0x61:
				# response bytes waiting
				apduout= self.HexArrayToList(self.PCSC_APDU['ACS_GET_RESPONSE']+[('%02x' % sw2)])
				result, sw1, sw2= self.pcsc_connection.transmit(apduout,protocol= self.pcsc_protocol)
			return result, sw1, sw2
		else:
			hresult, response = smartcard.scard.SCardControl( self.hcard, IOCTL_SMARTCARD_VENDOR_IFD_EXCHANGE, apdu )
			if hresult != smartcard.scard.SCARD_S_SUCCESS:
				return '',0x63,0x00
				#print 'Failed to control: ' + smartcard.scard.SCardGetErrorMessage(hresult)
				#os._exit(True)
			# evil hacky bodge as ACS returns only one byte for this APDU (ACS_DISABLE_AUTO_POLL)
			# and we ignore failure of we're running on firmware V1 as it doesn't support this command
			if apdu == [0xff,0x00,0x51,0x3f,0x00]:
				#print 'here!!!'
				if response == [0x3f] or self.hcard is not None:
					return '',0x90,0x00
				else:
					return '',0x63,0x00
			result = response[:-2]
			sw1 = response[-2]
			sw2 = response[-1]
			return result, sw1, sw2

	def acs_send_reader_apdu(self,apdu):
		"ACS send APDU to reader"
		myapdu= self.HexArraysToArray(apdu)
		apduout= self.HexArrayToList(myapdu)
		result, sw1, sw2= self.acs_transmit_apdu(apduout)
		self.data= self.ListToHex(result)
		self.errorcode= '%02X%02X' % (sw1,sw2)
		return True
	def acs_send_direct_apdu(self,apdu):
		"ACS send APDU direct to TAG"
		myapdu= self.HexArraysToArray(apdu)
		# build pseudo command for ACS 14443-A via NXP PN532
		lc= '%02x' % (len(myapdu) + len(self.PCSC_APDU['ACS_14443_A']))
		apduout= self.HexArrayToList(self.PCSC_APDU['ACS_DIRECT_TRANSMIT']+[lc]+self.PCSC_APDU['ACS_14443_A']+myapdu)		
		result, sw1, sw2= self.acs_transmit_apdu(apduout)
		self.errorcode= '%02X%02X' % (sw1,sw2)
		if self.errorcode == self.ISO_OK:
			self.data= self.ListToHex(result)
			# strip direct wrapper response and header to get TAG response and DATA
			if self.data[-4:] == self.ISO_OK and len(self.data) > 6:
				self.data= self.data[6:]
				self.data= self.data[:-4]
				return True
			else:
				self.errorcode= self.data[-4:]
				# strip ACS status and errorcode in case there is some data expected despite error
				self.data= self.data[6:-4]
				return False
			return True
		else:
			self.data= ''
			return False	
	def acs_rats(self,control):
		"ACS RATS on/off"
		if control:
			return self.acs_send_apdu(self.PCSC_APDU['ACS_RATS_14443_4_ON'])
		else:
			return self.acs_send_apdu(self.PCSC_APDU['ACS_RATS_14443_4_OFF'])
	def acs_mifare_login(self,block,key,keytype):
		"ACS Mifare Login"
		if keytype == 'BB':
			keytype= '61'
		else:
		   keytype= '60'
		loginblock= '%02x' % block
		if self.tagtype == self.ACS_TAG_MIFARE_1K or self.tagtype == self.ACS_TAG_MIFARE_4K:
			status= self.acs_send_apdu(self.PCSC_APDU['ACS_MIFARE_LOGIN']+[keytype]+[loginblock]+[key]+[self.uid])
		else:
			self.errorcode= self.ISO_NOINFO
			return False
		if not status or not self.data[:4] == self.ACS_DATA_OK or not self.data[4:6] == '00':
			self.errorcode= self.ISO_NOINFO
			return False
		self.errorcode= self.ISO_OK
		return True
	def acs_read_block(self,block):
		"ACS READ Block"
		readblock= '%02x' % block
		read= False
		if self.tagtype == self.ACS_TAG_MIFARE_ULTRA or self.tagtype == self.ACS_TAG_MIFARE_1K or self.tagtype == self.ACS_TAG_MIFARE_4K:
			status= self.acs_send_apdu(self.PCSC_APDU['ACS_READ_MIFARE']+[readblock])
			read= True
		if read:
			if not status or len(self.data) < 8 or not self.data[:4] == self.ACS_DATA_OK:
				self.errorcode= self.ISO_NOINFO
				return False
			# MIFARE ultralight returns 4 blocks although only asking for one, so truncate
			if self.tagtype == self.ACS_TAG_MIFARE_ULTRA:
				self.data= self.data[6:14]
			else:
				self.data= self.data[6:]
			self.errorcode= self.ISO_OK
			return True
		print "Can't read %s blocks" % self.ACS_TAG_TYPES[self.tagtype]
		os._exit(True)
	def acs_get_sam_serial(self):
		"ACS get SAM serial"
		return self.acs_send_apdu(self.PCSC_APDU['ACS_GET_SAM_SERIAL'])
	def acs_get_sam_id(self):
		"ACS get SAM id"
		return self.acs_send_apdu(self.PCSC_APDU['ACS_GET_SAM_ID'])
	def acs_set_retry(self,time):
		"ACS set retry"
		# 'time' currently ignored due to lack of documentation - hard wired to '1'
		return self.acs_send_apdu(self.PCSC_APDU['ACS_SET_RETRY'])
	def acs_select_tag(self):
		"ACS select TAG"
		# power antenna off and on to reset ISO14443-4 tags
		self.reset()
		self.acs_send_apdu(self.PCSC_APDU['ACS_POLL_MIFARE'])
		if not self.data[:4] == self.ACS_TAG_FOUND:
			# this shouldn't happen as the command should return number of tags to be 0 instead
			return False
		tags= int(self.data[4:6])
		if tags == 0:
			self.errorcode= self.PCSC_NO_CARD
			return False
		target= self.data[6:8]
		self.sens_res= self.data[8:12]
		self.sel_res= self.data[12:14]
		length= int(self.data[14:16])
		if length == 0:
			self.errorcode= self.PCSC_NO_CARD
			return False
		uid= self.data[16:16+length*2]
		try:
			self.tagtype= self.ACS_TAG_TYPES[self.sel_res]
		except:
			print 'unrecognised TAG type:', self.sel_res
			print 'full ACS return:', self.data
			self.tagtype= 'Unrecognised'
		self.data= uid
		return True
	def acs_get_firmware_revision(self):
		"ACS Get Firmware Revision"
                self.acs_send_reader_apdu(self.PCSC_APDU['ACS_GET_READER_FIRMWARE'])
		# 'special' APDU that doesn't return in the usual way. sw1,sw2 contains some of the data
		if len(self.data) > 0:
	                self.data += self.errorcode
			self.errorcode= self.ISO_OK
			return True
		self.data= ''
		self.errorcode= self.ISO_NOINFO
		return False
	def acs_power_on(self):
		"ACS Antenna Power On"
		return self.acs_send_apdu(self.PCSC_APDU['ACS_POWER_ON'])
	def acs_power_off(self):
		"ACS Antenna Power Off"
		return self.acs_send_apdu(self.PCSC_APDU['ACS_POWER_OFF'])
	# Global Platform specific commands
	def gp_external_authenticate(self,host_cryptogram,mac_key):
		"Global Platform external authenticate"
		cla=  '84'
		ins= 'EXTERNAL_AUTHENTICATE'
		p1= '00' # security level 0 - plaintext
		#p1= '01' # security level 1 - C-MAC
		p2= '00'
		data= self.ToHex(host_cryptogram)
		lc= '10' # needs to include MAC that will be added after mac generation
		mac= self.ToHex(self.DESMAC(self.ToBinary(cla+'82'+p1+p2+lc+data),mac_key,''))
		data += mac
		return self.send_apdu('','','','',cla,ins,p1,p2,lc,data,'')
	def gp_generate_session_key_01(self,hostchallenge,cardchallenge):
		"Global Platform generate session key from host and card challenges (SCP01)"
		derivation= cardchallenge[8:16]
		derivation += hostchallenge[0:8]
		derivation += cardchallenge[0:8]
		derivation += hostchallenge[8:16]
		return(derivation)
	def gp_get_data(self,object):
		"Global Platform get data"
		cla= self.CLA_GLOBAL_PLATFORM
		ins= 'GET_DATA'
		p1= object[0:2]
		p2= object[2:4]
		le= '00'
        	return self.send_apdu('','','','',cla,ins,p1,p2,'','',le)
	def gp_get_status(self,subset,control,aid):
		"Global Platform get status"
		cla= self.CLA_GLOBAL_PLATFORM
		ins= 'GET_STATUS'
		p1= subset
		p2= control
		data= '4F00' + aid
		lc= '%02x' % (len(data) / 2)
		le= '00'
		return self.send_apdu('','','','',cla,ins,p1,p2,lc,data,le)
	def gp_initialize_update(self,challenge):
		"Global Platform initialize update"
		cla= self.CLA_GLOBAL_PLATFORM
		ins= 'INITIALIZE_UPDATE'
		p1= '00'
		p2= '00'
		data= challenge
		lc= '%02x' % (len(data) / 2)
		le= '00'
		return self.send_apdu('','','','',cla,ins,p1,p2,lc,data,le)
	def gp_initialize_update_response_scp02(self,data):
		"return broken down Initialize Update response (SCP02) - Key Diversification (10), Key Info (2), Sequence Counter (2), Card Challenge (6), Card Cryptogram (8)"
		return data[0:20],data[20:24],data[24:28],data[28:40],data[40:56]
	# ISO 7816 commands
	def iso_7816_external_authenticate(self,response,key):
	        "7816 external authenticate"
        	ins= 'EXTERNAL_AUTHENTICATE'
        	lc= le= '%02x' % (len(response) / 2)
        	if self.send_apdu('','','','','',ins,'','',lc,response,le):
                	if self.MACVerify(self.data,key):
                        	return True
		return False
	def iso_7816_fail(self,code):
		"print 7816 failure code and exit"
		if code == self.ACG_FAIL:
			print "Application not implemented!"
			os._exit(True)
		print "Failed - reason code " + code + " (" + self.ISO7816ErrorCodes[code] + ")"
		print
		os._exit(True)
	def iso_7816_get_challenge(self,length):
        	"get random challenge - challenge will be in .data"
        	ins= 'GET_CHALLENGE'
        	le= '%02x' % length
        	if DEBUG:
                	print "DEBUG: requesting %d byte challenge" % length
        	return self.send_apdu('','','','','',ins,'','','','',le)
	def iso_7816_read_binary(self,bytes,offset):
		"7816 read binary - data read will be in .data"
	        ins= 'READ_BINARY'
        	hexoffset= '%04x' % offset
        	p1= hexoffset[0:2]
        	p2= hexoffset[2:4]
        	le= '%02x' % bytes
        	return self.send_apdu('','','','','',ins,p1,p2,'','',le)
	def iso_7816_select_file(self,file,control,options):
        	"7816 select file"
        	ins= 'SELECT_FILE'
        	lc= '%02x' % (len(file) / 2)
		p1= control
		p2= options
		data= file
        	return self.send_apdu('','','','','',ins,p1,p2,lc,data,'')
	def pcsc_send_apdu(self,apdu):
		# build and transmit PCSC apdu (list as appropriate, e.g. [cla,ins,p1,p2,lc,data,le...])
		apdustring= ''
		if self.readersubtype == self.READER_ACS:
			return self.acs_send_apdu(apdu)
		# apdu is a list which may contain long fields such as 'data', so first concatonate into
		# one long string, then break up into 2 char hex fields
		for d in apdu:
			apdustring += d
		apduout= self.HexToList(apdustring)
		result, sw1, sw2= self.pcsc_connection.transmit(apduout,protocol= self.pcsc_protocol)
		self.errorcode= '%02X%02X' % (sw1,sw2)
		self.data= self.ListToHex(result)
		# SCM readers need a little time to get over the excertion
#		if self.readersubtype == self.READER_SCM:
#			time.sleep(.1)
		if self.errorcode == self.ISO_OK:
			return True
		return False
	def send_apdu(self,option,pcb,cid,nad,cla,ins,p1,p2,lc,data,le):
		"send iso-7816-4 apdu"
		if not option:
			option= '1f'
			#option= '00'
		if not pcb:
			pcb= '02'
		if not cla:
			cla= '00'
		if not p1:
			p1= '00'
		if not p2:
			p2= '00'
		if self.readertype == self.READER_PCSC:
			return self.pcsc_send_apdu(cla+self.ISOAPDU[ins]+p1+p2+lc+data+le)
		if self.readertype == self.READER_LIBNFC:
			result = self.nfc.sendAPDU(cla+self.ISOAPDU[ins]+p1+p2+lc+data+le)
			self.data = result[0:-4]
			self.errorcode = result[len(result)-4:len(result)]
			if self.errorcode == self.ISO_OK:
				return True
			return False
		dlength= 5
		command= pcb+cla+self.ISOAPDU[ins]+p1+p2+lc+data+le
		dlength += len(data) / 2
		dlength += len(lc) / 2
		dlength += len(le) / 2
		if DEBUG:
			print 'sending: ' + 't' + '%02x' % dlength + option + command
		self.ser.write('t' + '%02x' % dlength + option + command)
		# need check for 'le' length as well
		ret= self.ser.readline()[:-2] 
		if DEBUG:
			print 'received:',ret
		self.errorcode= ret[len(ret) - 4:len(ret)]
		# copy data if more than just an error code (JCOP sometimes returns an error with data)
		if len(ret) > 8:
			self.data= ret[4:len(ret) - 4]
		else:
			self.data= ''
		if self.errorcode == self.ISO_OK:
			return True
		return False	
#		return ret[4:len(ret) - 4]
#		if not len(ret) / 2 == int(ret[0:2],16) + 1:
#			return False
#		return ret[4:int(le,16) * 2 + 4]
	def login_iclass(self,page,keynum):
		"login to an iclass page with a key stored on the reader"
		if not self.readersubtype == self.READER_OMNIKEY:
			self.errorcode= 'ABCD'
			return False
		ins= 'EXTERNAL_AUTHENTICATE'
		p1= '00'
		p2= '%02x' % keynum
		lc= '08'
		data= '0000000000000000'
		if not self.send_apdu('','','','','80',ins,p1,p2,lc,data,''):
			return False
		return True			
	def login(self,sector,keytype,key):
		"login to specified sector - returns True if successful, False if failed. If failure is due to an error, 'errorcode' will be set." 
		keytype= string.upper(keytype)
		# use transport key if none specified
		if not key:
			key= self.MIFARE_TK[keytype]
		if self.readertype == self.READER_ACG:
			if keytype == 'FF':
				keytype= 'AA'
			if not sector == '':
				if DEBUG:
					print 'sending:', 'l' + ('%02x' % sector) + keytype + key
				self.ser.write('l' + ('%02x' % sector) + keytype + key)
			else:
				if DEBUG:
					print 'sending:','l' + keytype + key
				self.ser.write('l' + keytype + key)
			if key == '':
				self.ser.write('\r')
			self.errorcode= self.ser.readline()[0]
			if DEBUG:
				print 'received:', self.errorcode
			if self.errorcode == 'L':
				self.errorcode= ''
				return True
			return False
		if self.readertype == self.READER_FROSCH:
			return self.frosch(self.FR_HTS_TagAuthent,'')
		if self.readertype == self.READER_PCSC:
			if self.readersubtype == self.READER_ACS:
				if self.acs_mifare_login(sector,key,keytype):
					return True
				else:
					return False
			# PCSC requires key to be loaded to reader, then login with key
			if not self.PCSC_Keys.has_key(key):
				# send key to reader and store in global PCSC_KEYS if not already sent
				apdu= []
				apdu += self.PCSC_APDU['LOAD_KEY']
				if self.readersubtype == self.READER_OMNIKEY:	
					keynum= len(self.PCSC_Keys)
					apdu += self.PCSC_NON_VOLATILE # load key to non-volatile reader memory
				else:
					apdu += self.PCSC_VOLATILE # load key to volatile reader memory
					keynum= len(self.PCSC_Keys) + 96 # SCM Mifare keys live at hex 60+
				if keytype == 'BB':
					keynumoffset= 1
				else:
					keynumoffset= 0
				apdu.append('%02x' % (keynum + keynumoffset)) # p2 - key number
				apdu.append('%02x' % (len(key) / 2)) # lc
				apdu.append(key) # data
				if not self.pcsc_send_apdu(apdu):
					return False
				if self.readersubtype == self.READER_OMNIKEY:
					# readers with non-volatile memory only need the key once
					self.PCSC_Keys[key]= keynum
			else:
				#use stored key if already sent	
				keynum= self.PCSC_Keys[key]
			# now try to authenticate
			return self.authenticate(sector,keytype, keynum)
	def authenticate(self,sector,keytype, keynum):
			keytype= string.upper(keytype)
			apdu= []
			apdu += self.PCSC_APDU['AUTHENTICATE']
			block= '%04x' % sector
			apdu.append(block[0:2]) # p1 sector msb
			apdu.append(block[2:4]) # p1 sector lsb
			if keytype == 'AA' or keytype == 'FF':
				apdu.append('60') # keytype
			elif keytype == 'BB':
				apdu.append('61') # keytype
			else:
				apdu.append(keytype)
			apdu.append('%02x' % keynum) # key number
			ret= self.pcsc_send_apdu(apdu)
			if ret == False:
				# let PCSC get over it!
				time.sleep(0.5)
			return ret
	def verify(self,keytype,key):
		keytype= string.upper(keytype)
		apdu= []
		apdu += self.PCSC_APDU['VERIFY']
		if keytype == 'AA' or keytype == 'FF':
			apdu.append('60') # keytype
		elif keytype == 'BB':
			apdu.append('61') # keytype
		apdu.append('00')
		apdu.append('%02x' % (len(key) / 2))
		apdu.append(key)
		ret= self.pcsc_send_apdu(apdu)
		if ret == False:
			# let PCSC get over it!
			time.sleep(0.5)
		return ret
	def readblock(self,block):
		if self.readertype == self.READER_FROSCH:
			if self.tagtype == self.HITAG1:
				return(self.frosch(self.FR_HT1_Read_Page,self.FR_PLAIN + chr(block))) 	
			if self.tagtype == self.HITAG2:
				return(self.frosch(self.FR_HT2_Read_Page,chr(block))) 	
		if self.readertype == self.READER_ACG:
			self.ser.write('r%02x' % block)
			self.data= self.ser.readline()[:-2]
			self.binary= ''
			if len(self.data) == 1:
				self.errorcode= self.data
				self.data= ''
				return False
			count= 0
			while count * 2 < len(self.data):
				self.binary += chr(int(self.data[count * 2:(count * 2) + 2],16))
				count += 1
			return True	
		if self.readertype == self.READER_PCSC:
			if self.readersubtype == self.READER_ACS:
				return self.acs_read_block(block)
			apdu= []
			apdu += self.PCSC_APDU['READ_BLOCK']
			hexblock= '%04x' % block
			apdu.append(hexblock[0:2]) # p1
			apdu.append(hexblock[2:4]) # p2
			# try reading with block length of 1 to provoke size error
			apdu.append('01') # le
			ret= self.pcsc_send_apdu(apdu)
			# if failure is due to wrong block size, use block size returned by card instead
			if self.errorcode.upper()[0:2] == '6C':
				apdu[-1]= self.errorcode[2:4]
				return self.pcsc_send_apdu(apdu)
			else:
				return ret
	def readMIFAREblock(self,block):
		if self.readblock(block):
			self.MIFAREdata= self.data
		else:
			return False
		count= 0
		while count * 2 < len(self.MIFAREdata):
			self.MIFAREbinary += chr(int(self.MIFAREdata[count * 2:(count * 2) + 2],16))
			count += 1
		return True
	def readvalueblock(self,block):
		self.ser.write('rv%02x' % block)
		self.MIFAREdata= self.ser.readline()[:-2]
		if len(self.MIFAREdata) != self.MIFAREVALUELEN:
			self.errorcode= self.MIFAREdata
			self.MIFAREdata= ''
			return False
		count= 0
		while count * 2 < len(self.MIFAREdata):
			self.MIFAREbinary += chr(int(self.MIFAREdata[count * 2:(count * 2) + 2],16))
			count += 1
		return True
	def writeblock(self,block,data):
		if self.readertype == self.READER_FROSCH:
			#if self.tagtype == self.HITAG1:
			#	return(self.frosch(self.FR_HT1_Read_Page,self.FR_PLAIN + chr(block))) 	
			if self.tagtype == self.HITAG2:
				return(self.frosch(self.FR_HT2_Write_Page,chr(block) + self.ToBinary(data))) 	
		if self.readertype == self.READER_ACG:
			self.ser.write('w%02x%s' % (block,data))
			x= self.ser.readline()[:-2]
			if x == string.upper(data):
				self.errorcode= ''
				return True
			self.errorcode= x
			return False
		if self.readertype == self.READER_PCSC:
			apdu= []
			apdu += self.PCSC_APDU['UPDATE_BLOCK']
			hexblock= '%04x' % block
			apdu.append(hexblock[0:2]) # p1
			apdu.append(hexblock[2:4]) # p2
			apdu.append('%02x' % (len(data) / 2)) # le
			apdu.append(data)
			return self.pcsc_send_apdu(apdu)
	def writevalueblock(self,block,data):
		self.ser.write('wv%02x%s' % (block,data))
                x= self.ser.readline()[:-2]
                if x == string.upper(data):
                        self.errorcode= ''
                        return True
                self.errorcode= x
                return False
	def frosch(self,command,data):
		"send frosch commands with check digit"
		command += data
		commandlen= len(command)
		bcc= self.frosch_bcc_out(command,commandlen + 1)
		# send length + command + checkdigit
		if DEBUG:
			print 'Sending: ', 
			self.HexPrint(chr(commandlen + 1) + command + chr(bcc))
		self.ser.write(chr(commandlen + 1) + command + chr(bcc))
		ret= ''
		# perform a blocking read - returned byte is number of chars still to read
		ret += self.ser.read(1)
		# if read times out, reset may be required for normal read mode
		if len(ret) == 0:
			if command == self.FR_HT2_Read_PublicB or command == self.FR_HT2_Read_Miro:
				self.frosch(self.FR_RWD_Stop_Cmd,'')
			self.errorcode= self.FR_TIMEOUT
			return False
		# now read the rest
		ret += self.ser.read(ord(ret[0]))
		if DEBUG:
			print 'ret: %d ' % len(ret),
			self.HexPrint(ret)
		# check integrity of return
		bcc= self.frosch_bcc_in(ret,0)
		if not bcc == ord(ret[len(ret) - 1]):
			# may be reporting an error with wrong BCC set
			if ret[0] == chr(0x02) and not ret[1] == chr(0x00):
				self.data= ''
				self.errorcode= self.ToHex(ret[1])
				return False
			print 'Frosch error! Checksum error:',
			self.HexPrint(ret)
			print 'Expected BCC: %02x' % bcc
			os._exit(True)
		status= ret[1]
		if status == self.FR_NO_ERROR:
			self.errorcode= ''
			# for consistency with ACG, data is converted to printable hex before return
			self.data= self.ToHex(ret[2:len(ret) - 1])
			return True
		else :
			self.errorcode= self.ToHex(status)
			self.data= ''
			if DEBUG:
				print "Frosch error:", int(self.errorcode,16) - 256
			# reader may need resetting to normal read mode
			if command == self.FR_HT2_Read_PublicB or command == self.FR_HT2_Read_Miro:
				self.frosch(self.FR_RWD_Stop_Cmd,'')
			return False
	def frosch_bcc(self,data,seed):
		bcc= seed
		if self.FR_BCC_Mode == self.FR_COMMAND_MODE:
			for x in range(len(data)):
				bcc= xor(bcc,ord(data[x]))
		else:
			for x in range(len(data)):
				bcc += ord(data[x])
			bcc= int(bcc & 0xff)
		return bcc	
	def frosch_bcc_in(self,data,seed):
		return self.frosch_bcc(data[:len(data) - 1],seed)
	def frosch_bcc_out(self,data,seed):
		return self.frosch_bcc(data,seed)
	def frosch_key_init_mode(self,passwd):
		"enter key init mode"
		status= self.frosch(self.FR_RWD_Key_Init_Mode,self.ToBinary(passwd))
		# frosch BCC calculation mode changes once we enter key init mode
		if status:
			self.FR_BCC_Mode= self.FR_KEY_INIT_MODE
		return status
	def frosch_read_ee_data(self,item):
		"read RWD EEPROM"
		# item defines which personalization data is to be read
		# 0x00 ... Password
		# 0x01 ... Key A
		# 0x02 ... Key B
		# 0x03 ... Logdata 0A
		# 0x04 ... Logdata 0B
		# 0x05 ... Logdata 1A
		# 0x06 ... Logdata 1B
		return self.frosch(self.FR_RWD_KI_Read_EE_Data,self.ToBinary(item))
	def demotag(self,command,data):
		"send DemoTag commands"
		if self.ser.write(command + data):
                	x= self.ser.readline()[:-2]
			if x == self.DT_ERROR:
				self.errorcode= x
				return False
			self.data= x
			return True
		return False
	#
	# data manipulation
	#
	def GetRandom(self,size):
        	data= ''
        	for x in range(size):
                	data += '%02x' % int(random.uniform(0,0xff))
        	return data
	def Parity(self,data,parity):
		# return parity bit to make odd or even as required
		myparity= 0
		for x in range(len(data)):
			myparity += int(data[x],2)
		myparity %= 2
		return xor(myparity,parity)
	def Unique64Bit(self,data):
		"convert binary ID to Unique formatted 64 bit data block"
		# standard header == 9 bits of '1'
		out= '111111111'
		# break output into 4 bit chunks and add parity
		colparity= [0,0,0,0]
		for x in range(0,len(data),4):
			parity= 0
			chunk= data[x:x+4]
			for y in range(4):
				parity += int(chunk[y],2)
				colparity[y] += int(chunk[y],2)
			out += chunk + '%s' % (int(parity) % 2)
		# add column parity
		for x in range(4):
			out += '%s' % (int(colparity[x]) % 2)
		# add stop bit
		out += '0'
		return out
	def UniqueToEM(self,data):
		"convert Unique ID to raw EM4x02 ID"
		# swap words
		tmp= ''
		for x in range(5):
			tmp += data[x * 2 + 1] + data[x * 2]
		# reverse bits
		return self.ToBinaryString(self.ToBinary(tmp))[::-1]
	def EMToUnique(self,data):
		"convert raw EM4x02 ID to Unique"
		return self.ToHex(self.BitReverse(self.ToBinary(data)))
	def HexToQ5(self,data):
		"conver human readable HEX to Q5 ID"
		return self.ToBinaryString(self.ToBinary(data))
	def crcccitt(self,data):
		crcvalue= 0x0000
		for x in range(len(data)):
			crcvalue= self.crc(crcvalue,data[x],MASK_CCITT)
		return crcvalue
	def crc(self, crc, data, mask=MASK_CRC16):
		for char in data:
			c = ord(char)
			c = c << 8
		for j in xrange(8):
			if (crc ^ c) & 0x8000:
				crc = (crc << 1) ^ mask
			else:
				crc = crc << 1
			c = c << 1
		return crc & 0xffff
	def crc16(self,data):
		crcValue=0x0000
		crc16tab = (0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280,
		0xC241, 0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481,
		0x0440, 0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81,
		0x0E40, 0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880,
		0xC841, 0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81,
		0x1A40, 0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80,
		0xDC41, 0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680,
		0xD641, 0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081,
		0x1040, 0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281,
		0x3240, 0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480,
		0xF441, 0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80,
		0xFE41, 0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881,
		0x3840, 0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80,
		0xEA41, 0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81,
		0x2C40, 0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681,
		0x2640, 0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080,
		0xE041, 0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281,
		0x6240, 0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480,
		0xA441, 0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80,
		0xAE41, 0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881,
		0x6840, 0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80,
		0xBA41, 0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81,
		0x7C40, 0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681,
		0x7640, 0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080,
		0xB041, 0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280,
		0x9241, 0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481,
		0x5440, 0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81,
		0x5E40, 0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880,
		0x9841, 0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81,
		0x4A40, 0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80,
		0x8C41, 0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680,
		0x8641, 0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081,
		0x4040)
		for ch in data:
			tmp=crcValue^(ord(ch))
			crcValue=(crcValue>> 8)^crc16tab[(tmp & 0xff)]
		return crcValue
	def MIFAREmfb(self,data):
		"Set variables from standard MIFARE manufacturer block (block 0 sector 0)"
		self.MIFAREserialnumber= data[0:8]
		self.MIFAREcheckbyte= data[8:10]
		self.MIFAREmanufacturerdata= data[10:32]
	def MIFAREkb(self,data):
		"Set variables from standard MIFARE key block (trailing sector)"
		self.MIFAREkeyA= data[0:12]
		self.MIFAREaccessconditions= data[12:18]
		self.MIFAREaccessconditionsuserbyte= data[18:20]
		self.MIFAREC1= int(data[14:16],16) >> 4
		self.MIFAREC2= int(data[16:18],16) & 0x0f
		self.MIFAREC3= (int(data[16:18],16) & 0xf0) >> 4
		self.MIFAREblock0AC= str(self.MIFAREC1 & 0x01) + str(self.MIFAREC2 & 0x01) + str(self.MIFAREC3 & 0x01)
		self.MIFAREblock1AC= str((self.MIFAREC1 & 0x02) >> 1) + str((self.MIFAREC2 & 0x02) >> 1) + str((self.MIFAREC3 & 0x02) >> 1)
		self.MIFAREblock2AC= str((self.MIFAREC1 & 0x04) >> 2) + str((self.MIFAREC2 & 0x04) >> 2) + str((self.MIFAREC3 & 0x04) >> 2)
		self.MIFAREblock3AC= str((self.MIFAREC1 & 0x08) >> 3) + str((self.MIFAREC2 & 0x08) >> 3) + str((self.MIFAREC3 & 0x08) >> 3)
		self.MIFAREkeyB= data[20:32]
	def MIFAREvb(self,data):
		"Set variables from standard MIFARE value block"
		self.MIFAREvalue= data[0:4]
		self.MIFAREvalueinv= data[4:8]
		self.MIFAREvalue2= data[8:12]
		self.MIFAREaddr= data[12]
		self.MIFAREaddrinv= data[13]
		self.MIFAREaddr2= data[14]
		self.MIFAREaddrinv2= data[15]
	def MRPmrzl(self,data):
		"Set variables from Machine Readable Zone (Lower)"
		self.MRPnumber= data[0:9]
		self.MRPnumbercd= data[9]
		self.MRPnationality= data[10:13]
		self.MRPdob= data[13:19]
		self.MRPdobcd= data[19]
		self.MRPsex= data[20]
		self.MRPexpiry= data[21:27]
		self.MRPexpirycd= data[27]
		self.MRPoptional= data[28:42]
		self.MRPoptionalcd= data[42]
		self.MRPcompsoitecd= data[43]
	def BitReverse(self,data):
		"Reverse bits - MSB to LSB"
		output= ''
		for y in range(len(data)):
			outchr= ''
			for x in range(8):
				outchr += str(ord(data[y]) >> x & 1)
			output += str(chr(int(outchr,2)))
		return output
	def HexReverse(self,data):
		"Reverse HEX characters"
		output= ''
		for y in reversed(range(len(data))):
			output += data[y]
		return output
	def HexBitReverse(self,data):
		"Convert HEX to Binary then bit reverse and convert back"
		return self.ToHex(self.BitReverse(self.ToBinary(data)))
	def HexByteReverse(self,data):
		"Reverse order of Hex pairs"
		output= ''
		y= len(data) - 2
		while y >= 0:
			output += data[y:y+2]
			y -= 2
		return output
	def NibbleReverse(self,data):
		"Reverse Nibbles"
		output= ''
		for y in range(len(data)):
			leftnibble= ''
			rightnibble= ''
			for x in range(4):
				leftnibble += str(ord(data[y]) >> x & 1)
			for x in range(4,8):
				rightnibble += str(ord(data[y]) >> x & 1)
			output += str(chr(int(rightnibble + leftnibble,2)))
		return output
	def HexNibbleReverse(self,data):
		"Convert HEX to Binary then reverse nibbles and convert back"
		return self.ToHex(self.NibbleReverse(self.ToBinary(data)))
	def ToHex(self,data):
		"convert binary data to hex printable"
        	string= ''
        	for x in range(len(data)):
                	string += '%02x' % ord(data[x])
		return string
	def HexPrint(self,data):
        	print self.ToHex(data)
	def ReadablePrint(self,data):
		out= ''
		for x in range(len(data)):
			if data[x] >= ' ' and data[x] <= '~':
				out += data[x]
			else:
				out += '.'
		return out
	def ListToHex(self,data):
		string= ''
		for d in data:
			string += '%02X' % d
		return string
	def HexArrayToString(self,array):
		# translate array of strings to single string
		out= ''
		for n in array:
			out += n
		return out
	def HexArraysToArray(self,array):
		# translate an array of strings to an array of 2 character strings
		temp= self.HexArrayToString(array)
		out= []
		n= 0
		while n < len(temp):
			out.append(temp[n:n+2])
			n += 2
		return out
	def HexArrayToList(self,array):
		# translate array of 2 char HEX to int list
		# first make sure we're dealing with a single array
		source= self.HexArraysToArray(array)
		out= []
		for n in source:
			out.append(int(n,16))
		return out
	def HexToList(self,string):
		# translate string of 2 char HEX to int list
		n= 0
		out= []
		while n < len(string):
			out.append(int(string[n:n+2],16))
			n += 2
		return out
	def ToBinary(self,string):
		"convert hex string to binary characters"
        	output= ''
        	x= 0
        	while x < len(string):
                	output += chr(int(string[x:x + 2],16))
                	x += 2
        	return output
	def BinaryPrint(self,data):
		"print binary representation"
		print self.ToBinaryString(data)
	def ToBinaryString(self,data):
		"convert binary data to printable binary ('01101011')"
		output= ''
		string= self.ToHex(data)
		for x in range(0,len(string),2):
			for y in range(7,-1,-1):
				output += '%s' % (int(string[x:x+2],16) >> y & 1)
		return output
	def BinaryToManchester(self,data):
		"convert binary string to manchester encoded string"
		output= ''
		for bit in data:
			if bit == '0':
				output += '01'
			else:
				output += '10'
		return output
	def DESParity(self,data):
        	adjusted= ''
        	for x in range(len(data)):
                	y= ord(data[x]) & 0xfe
                	parity= 0
                	for z in range(8):
                        	parity += y >>  z & 1
                	adjusted += chr(y + (not parity % 2))
        	return adjusted
	def DESKey(self,seed,type,length):
		d= seed + type	
		kencsha= SHA.new(d)
		k= kencsha.digest()
		kp= self.DESParity(k)
		return(kp[:length])
	def PADBlock(self,block):
		"add DES padding to data block"
		# call with null string to return an 8 byte padding block
		# call with an unknown sized block to return the block padded to a multiple of 8 bytes
        	for x in range(8 - (len(block) % 8)):
                	block += self.DES_PAD[x]
		return block
	def DES3MAC(self,message,key,ssc):
		"iso 9797-1 Algorithm 3 (Full DES3)"
		tdes= DES3.new(key,DES3.MODE_ECB,self.DES_IV)
		if(ssc):
			mac= tdes.encrypt(self.ToBinary(ssc))
		else:
			mac= self.DES_IV
		message += self.PADBlock('')
		for y in range(len(message) / 8):
			current= message[y * 8:(y * 8) + 8]
			left= ''
			right= ''
			for x in range(len(mac)):
				left += '%02x' % ord(mac[x])
				right += '%02x' % ord(current[x])
			machex= '%016x' % xor(int(left,16),int(right,16))
			mac= tdes.encrypt(self.ToBinary(machex))
		# iso 9797-1 says we should do the next two steps for "Output Transform 3"
		# but they're obviously redundant for DES3 with only one key, so I don't bother!
		#mac= tdes.decrypt(mac)
		#mac= tdes.encrypt(mac)
		return mac
	def DESMAC(self,message,key,ssc):
		"iso 9797-1 Algorithm 3 (Retail MAC)"
		# DES for all blocks
		# DES3 for last block
	        tdesa= DES.new(key[0:8],DES.MODE_ECB,self.DES_IV)
        	tdesb= DES.new(key[8:16],DES.MODE_ECB,self.DES_IV)
        	if(ssc):
                	mac= tdesa.encrypt(self.ToBinary(ssc))
        	else:
                	mac= self.DES_IV
		message += self.PADBlock('')
        	for y in range(len(message) / 8):
                	current= message[y * 8:(y * 8) + 8]
                	left= right= ''
                	for x in range(len(mac)):
                        	left += '%02x' % ord(mac[x])
                        	right += '%02x' % ord(current[x])
                	machex= '%016x' % xor(int(left,16),int(right,16))
                	mac= tdesa.encrypt(self.ToBinary(machex))
        	mac= tdesb.decrypt(mac)
        	return tdesa.encrypt(mac)
	def MACVerify(self,message,key):
		mess= self.ToBinary(message[:len(message)- 16])
		mac= self.DESMAC(mess,key,'')
		if not mac == self.ToBinary(message[len(message) -16:]):
			print 'MAC Error!'
			print 'Expected MAC: ', message[len(message) -16:]
			print 'Actual MAC:   ',
			self.HexPrint(mac)
			return(False)
		return(True)
	def SSCIncrement(self,ssc):
		out= int(self.ToHex(ssc),16) + 1
		return self.ToBinary("%016x" % out)
	def TRANSITIDEncode(self,data):
		"Encode TRANSIT ID"
		# start sentinel
		out= '0000000000000000'
		# UID
		out += self.ToBinaryString(self.ToBinary(data))
		# LRC
		lrc= self.TRANSITLRC(out[16:48])
		out += self.ToBinaryString(chr(lrc))
		# end sentinel
		out += self.ToBinaryString(chr(0xf2))
		return out
	def TRANSITID(self,data):
		"Decode TRANSIT ID"
		# check for start sentinel
		if(data[0:16] != '0000000000000000'):
			print 'Start sentinel not found! (0000000000000000)'
			return 0
		# check for end sentinel
		if(int(data[56:],2) != 0xf2):
			print 'End sentinel not found! (11110010)'
			return 0
		lrc= self.TRANSITLRC(data[16:48])
		if(lrc != int(data[48:56],2)):
			print 'LRC mismatch: %02X should be %02X!' % (int(data[48:56],2),lrc)
			return 0
		out= '%08X' % int(data[16:48],2)
		return out
	def TRANSITIDPrint(self,data):
		out= self.TRANSITID(data)
		if(out != 0):
			print 'UID:', out
		else:
			print 'Invalid ID!'
	def TRANSITLRC(self,data):
		"Calculate TRANSIT LRC"
		i= 0
		lrc= 0x00
		# rolling XOR
                while(i < 4):
                        lrc ^= (int(data[(i) * 8:(i+1) * 8],2)) & 0xff
                        i += 1
		# final byte XOR
                lrc ^= 0x5a & 0xff
		return lrc
	def FDXBID(self,data):
		"Decode FDX-B ID"
        	out= self.HexReverse(data)
        	hexout= self.ToHex(self.NibbleReverse(self.ToBinary(out)))
		# Application ID
        	self.FDXBAPP= hexout[:4]
		# Country Code
        	ccode= hexout[4:7]
        	self.FDXBCCODE= int(ccode,16) >> 2
		# Human Readable CCODE
		if "%d" % self.FDXBCCODE in self.ISO3166CountryCodes:
			self.FDXBCCODEHR= self.ISO3166CountryCodes["%d" % self.FDXBCCODE]
		else:
			self.FDXBCCODEHR= 'Undefined - see http://www.icar.org/manufacturer_codes.htm'
		# National ID
        	natid= hexout[6:16]
        	self.FDXBNID= int(natid,16) &0x3fffffffff
	def FDXBIDEncode(self,appid,ccode,natid):
		"Encode FDX-B ID"
		hexccode= "%03x" % (int(ccode,10) << 2)
		glue = int(hexccode[-1:],16) & 0xc
		hexccode = hexccode[:-1]
		hexid= "%010x" % int(natid,10)
		glue = glue | (int(hexid[:1],16) & 0x3)
		hexglue = "%01x" % glue
		hexid = hexid[1:]
		rawid= appid + hexccode + hexglue + hexid
		nibbleid= self.NibbleReverse(self.ToBinary(rawid))
		hexout= self.HexReverse(self.ToHex(nibbleid))
		return hexout 
	def FDXBIDPrint(self,data):
		self.FDXBID(data)
        	print 'Application Identifier: ', self.FDXBAPP
        	print 'Country Code: ',
        	print self.FDXBCCODE,
        	print  "(" + self.FDXBCCODEHR + ")"
        	print 'National ID: ',
        	print self.FDXBNID
	def FDXBID128Bit(self,data):
		"generate raw 128 bit FDX-B data from FDX-B ID"
		idbin= self.ToBinaryString(self.ToBinary(data))
		# construct FDX-B encoded blocks
		out= ''
		# header is ten zeros and a '1'
		header= '00000000001'
		out += header
		# break id into 8 bit chunks with a trailing '1' on each
		for x in range(0,len(idbin),8):
			out += idbin[x:x+8] + '1'
		# add 16 CRC-CCITT error detection bits
		crc= '%04x' % self.crcccitt(self.ToBinary(data))
		crcbin= self.ToBinaryString(self.ToBinary(crc))
		# crc is transmitted LSB first with trailing '1's
		out += crcbin[0:8] + '1'
		out += crcbin[8:16] + '1'
		# add 3 sets of trailer bits (RFU)
		trailer= '000000001'
		for x in range(3):
			out += trailer
		return out
	def FDXBID128BitDecode(self,data):
		"convert raw 128 bit FDX-B data to FDX-B ID"
		#strip off header
		y= data[11:]
		#strip off trailing '1' from the first 8 9-bit groups
		out= ''
		for x in range(0,72,9):
			out += y[x:x+8]
		# ignore the rest - CRC etc.
		return '%016x' % int(out,2)	
	def PCSCGetTagType(self,atr):
		"get currently selected tag type from atr"
		if atr[8:12] == self.PCSC_CSC:
			ss= atr[24:26]
			return self.PCSC_SS[ss]
		else:
			return 'SMARTCARD'
	def PCSCPrintATR(self,data):
		"print breakdown of HEX ATR"
		print '    ATR:', data
		if data[0:2].upper() == '3B':
			print '         3B  Initial Header' 
		else:
			print 'ATR not recognised!'
			return False
		if data[2] == '8':
			print '           8  No TA1, TB1, TC1 only TD1 is following'
		histlen= int(data[3],16)
		print '            %s  %d bytes historical data follow' % (data[3] , histlen)
		if data[4] == '8':
			print '             8  No TA2, TB2, TC2 only TD2 is following'
		if data[5] == '0':
			print '              0  T = 0'
		if data[6] == '0':
			print '               0  No TA3, TB3, TC3, TD3 following'
		if data[7] == '1':
			print '                1  T = 1'
		if data[8:12] == self.PCSC_CSC:
			print '                 Detected STORAGECARD'
			print '     Historical:', data[8:-2]
			print '                 80  Status indicator may be present (COMPACT-TLV object)'
			print '                   4F  Application Identifier presence indicator'
			applen= int(data[12:14],16)
			print '                     %s  %d bytes follow' % (data[12:14] , applen) 
			print '                 RID:  %s ' % data[14:24],
			if data[14:24].upper() == self.PCSC_RID:
				print 'PC/SC Workgroup'
			else:
				print 'Unknown RID'
			pixlen= applen - 5
			print '                           PIX:  %s' % data[24:24 + pixlen * 2]
			ss= data[24:26]
			print '                            SS:  %s  %s' % (ss , self.PCSC_SS[ss]),
			# if card is ISO15693 print manufacturer name
			if 9 <= int(ss,16) <= 12:
				try:
					print '(%s)' % self.ISO7816Manufacturer[self.uid[2:4]]
				except:
					print '(Uknown Manufacturer)'
			else:
				print
			print '                            Name:  %s  %s' % (data[26:30] , self.PCSC_NAME[data[26:30]])
			print '                                 RFU:  %s' % data[30:-2]
			spaces= histlen * 2
		else:
			print '                 Detected SMARTCARD'
			print '            ATS:',self.pcsc_ats,'-',
			print self.ReadablePrint(self.ToBinary(self.pcsc_ats))
			# if ats starts with '00', '10' or '8X' it is an ISO-7816-4 card
			atsbyte= self.pcsc_ats[0:2]
			if atsbyte == '00' or atsbyte == '10' or self.pcsc_ats[0] == '8':
				print '       Category: %s  Format according to ISO/IEC 7816-4' % atsbyte
			else:
				print '       Category: %s  Proprietary format' % atsbyte
			spaces= len(self.pcsc_ats)
		space= ''
		for x in range(spaces):
			space += ' '
			
		print space + '   Checksum TCK: ' + data[-2:],
		# calculate checksum excluding Initial Header and TCK
		tck= 0
		x= 2
		while x < len(data) - 2:
			tck= xor(tck,int(data[x:x+2],16))
			x += 2
		if int(data[-2:],16) == tck:
			print '(OK)'
			return True
		else:
			print '(Checksum error: %02x)' % tck
			return False

	def shutdown(self):
		if self.readertype == self.READER_LIBNFC:
			self.nfc.powerOff()
			self.nfc.deconfigure()
		os._exit(False)
