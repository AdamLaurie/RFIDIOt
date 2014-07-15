#!/usr/bin/python

#
# pynfc.py - Python wrapper for libnfc
# version 0.2 (should work with libnfc 1.2.1 and 1.3.0)
# version 0.2a - tweaked by rfidiot for libnfc 1.6.0-rc1 october 2012
# Nick von Dadelszen (nick@lateralsecurity.com)
# Lateral Security (www.lateralsecurity.com)

#  Thanks to metlstorm for python help :)
#
# This code is copyright (c) Nick von Dadelszen, 2009, All rights reserved.
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

import ctypes
import ctypes.util
import binascii
import logging
import time
import readline
import string
import rfidiotglobals

# nfc_property enumeration
NP_TIMEOUT_COMMAND		= 0x00
NP_TIMEOUT_ATR			= 0x01
NP_TIMEOUT_COM			= 0x02
NP_HANDLE_CRC			= 0x03
NP_HANDLE_PARITY		= 0x04
NP_ACTIVATE_FIELD		= 0x05
NP_ACTIVATE_CRYPTO1		= 0x06
NP_INFINITE_SELECT		= 0x07
NP_ACCEPT_INVALID_FRAMES	= 0x08
NP_ACCEPT_MULTIPLE_FRAMES	= 0x09
NP_AUTO_ISO14443_4		= 0x0a
NP_EASY_FRAMING			= 0x0b
NP_FORCE_ISO14443_A		= 0x0c
NP_FORCE_ISO14443_B		= 0x0d
NP_FORCE_SPEED_106		= 0x0e

# NFC modulation type enumeration
NMT_ISO14443A		= 0x01
NMT_JEWEL		= 0x02
NMT_ISO14443B		= 0x03
NMT_ISO14443BI		= 0x04
NMT_ISO14443B2SR	= 0x05
NMT_ISO14443B2CT	= 0x06
NMT_FELICA		= 0x07
NMT_DEP			= 0x08

# NFC baud rate enumeration
NBR_UNDEFINED		= 0x00
NBR_106			= 0x01
NBR_212			= 0x02
NBR_424			= 0x03
NBR_847			= 0x04

#NFC D.E.P. (Data Exchange Protocol) active/passive mode
NDM_UNDEFINED		= 0x00
NDM_PASSIVE		= 0x01
NDM_ACTIVE		= 0x02

# Mifare commands
MC_AUTH_A 		= 0x60
MC_AUTH_B 		= 0x61
MC_READ 		= 0x30
MC_WRITE 		= 0xA0
MC_TRANSFER 		= 0xB0
MC_DECREMENT 		= 0xC0
MC_INCREMENT 		= 0xC1
MC_STORE 		= 0xC2

# PN53x specific errors */
ETIMEOUT        	= 0x01
ECRC            	= 0x02
EPARITY         	= 0x03
EBITCOUNT       	= 0x04
EFRAMING        	= 0x05
EBITCOLL        	= 0x06
ESMALLBUF       	= 0x07
EBUFOVF         	= 0x09
ERFTIMEOUT      	= 0x0a
ERFPROTO        	= 0x0b
EOVHEAT         	= 0x0d
EINBUFOVF       	= 0x0e
EINVPARAM       	= 0x10
EDEPUNKCMD      	= 0x12
EINVRXFRAM      	= 0x13
EMFAUTH         	= 0x14
ENSECNOTSUPP    	= 0x18    # PN533 only
EBCC            	= 0x23
EDEPINVSTATE    	= 0x25
EOPNOTALL       	= 0x26
ECMD            	= 0x27
ETGREL          	= 0x29
ECID            	= 0x2a
ECDISCARDED     	= 0x2b
ENFCID3         	= 0x2c
EOVCURRENT      	= 0x2d
ENAD            	= 0x2e

MAX_FRAME_LEN 		= 264
MAX_DEVICES 		= 16
BUFSIZ 			= 8192
MAX_TARGET_COUNT 	= 1

DEVICE_NAME_LENGTH	= 256
DEVICE_PORT_LENGTH	= 64
NFC_CONNSTRING_LENGTH	= 1024

class NFC_ISO14443A_INFO(ctypes.Structure):
	_pack_ = 1
	_fields_ = [('abtAtqa', ctypes.c_ubyte * 2),
		    ('btSak', ctypes.c_ubyte),
		    ('uiUidLen', ctypes.c_size_t),
		    ('abtUid', ctypes.c_ubyte * 10),
		    ('uiAtsLen', ctypes.c_size_t),
		    ('abtAts', ctypes.c_ubyte * 254)]

class NFC_FELICA_INFO(ctypes.Structure):
	_pack_ = 1
	_fields_ = [('szLen', ctypes.c_size_t),
		    ('btResCode', ctypes.c_ubyte),
		    ('abtId', ctypes.c_ubyte * 8),
		    ('abtPad', ctypes.c_ubyte * 8),
		    ('abtSysCode', ctypes.c_ubyte * 2)]

class NFC_ISO14443B_INFO(ctypes.Structure):
	_pack_ = 1
	_fields_ = [('abtPupi', ctypes.c_ubyte * 4),
		    ('abtApplicationData', ctypes.c_ubyte * 4),
		    ('abtProtocolInfo', ctypes.c_ubyte * 3),
		    ('ui8CardIdentifier', ctypes.c_ubyte)]

class NFC_ISO14443BI_INFO(ctypes.Structure):
	_pack_ = 1
	_fields_ = [('abtDIV', ctypes.c_ubyte * 4),
		    ('btVerLog', ctypes.c_ubyte),
		    ('btConfig', ctypes.c_ubyte),
		    ('szAtrLen', ctypes.c_size_t),
		    ('abtAtr', ctypes.c_ubyte * 33)]

class NFC_ISO14443B2SR_INFO(ctypes.Structure):
	_pack_ = 1
	_fields_ = [('abtUID', ctypes.c_ubyte * 8)]


class NFC_ISO14443B2CT_INFO(ctypes.Structure):
	_pack_ = 1
	_fields_ = [('abtUID', ctypes.c_ubyte * 4),
		    ('btProdCode', ctypes.c_ubyte),
		    ('btFabCode', ctypes.c_ubyte)]

class NFC_JEWEL_INFO(ctypes.Structure):
	_pack_ = 1
	_fields_ = [('btSensRes', ctypes.c_ubyte * 2),
		    ('btId', ctypes.c_ubyte * 4)]

class NFC_DEP_INFO(ctypes.Structure):
	_pack_ = 1
	_fields_ = [('abtNFCID3', ctypes.c_ubyte * 10),
		    ('btDID', ctypes.c_ubyte),
		    ('btBS', ctypes.c_ubyte),
		    ('btBR', ctypes.c_ubyte),
		    ('btTO', ctypes.c_ubyte),
		    ('btPP', ctypes.c_ubyte),
		    ('abtGB', ctypes.c_ubyte * 48),
		    ('szGB', ctypes.c_size_t),
		    ('ndm', ctypes.c_ubyte)]

class NFC_TARGET_INFO(ctypes.Union):
	_pack_ = 1
	_fields_ = [('nai', NFC_ISO14443A_INFO),
		    ('nfi', NFC_FELICA_INFO),
		    ('nbi', NFC_ISO14443B_INFO),
		    ('nii', NFC_ISO14443BI_INFO),
		    ('nsi', NFC_ISO14443B2SR_INFO),
		    ('nci', NFC_ISO14443B2CT_INFO),
		    ('nji', NFC_JEWEL_INFO),
		    ('ndi', NFC_DEP_INFO)]

class NFC_CONNSTRING(ctypes.Structure):
	_pack_ = 1
	_fields_ = [('connstring', ctypes.c_ubyte * NFC_CONNSTRING_LENGTH)]

class NFC_MODULATION(ctypes.Structure):
	_pack_ = 1
	_fields_ = [('nmt', ctypes.c_uint),
		    ('nbr', ctypes.c_uint)]

class NFC_TARGET(ctypes.Structure):
	_pack_ = 1
	_fields_ = [('nti', NFC_TARGET_INFO),
		    ('nm', NFC_MODULATION)]

#class NFC_DEVICE(ctypes.Structure):
#	_fields_ = [('driver', ctypes.pointer(NFC_DRIVER),
#		    ('driver_data', ctypes.c_void_p),
#		    ('chip_data', ctypes.c_void_p),
#		    ('name', ctypes.c_ubyte * DEVICE_NAME_LENGTH),
#		    ('nfc_connstring', ctypes.c_ubyte * NFC_CONNSTRING_LENGTH),
#		    ('bCrc', ctypes.c_bool),
#		    ('bPar', ctypes.c_bool),
#		    ('bEasyFraming', ctypes.c_bool),
#		    ('bAutoIso14443_4', ctypes.c_bool),
#		    ('btSupportByte', ctypes.c_ubyte).
#		    ('last_error', ctypes.c_byte)]

#class NFC_DEVICE_DESC_T(ctypes.Structure):
#	_fields_ = [('acDevice',ctypes.c_char * BUFSIZ),
#		    ('pcDriver',ctypes.c_char_p),
#		    ('pcPort',ctypes.c_char_p),
#		    ('uiSpeed',ctypes.c_ulong),
#		    ('uiBusIndex',ctypes.c_ulong)]

#NFC_DEVICE_LIST = NFC_DEVICE_DESC_T * MAX_DEVICES
NFC_DEVICE_LIST = NFC_CONNSTRING * MAX_DEVICES

class ISO14443A(object):
	def __init__(self, ti):
		self.uid = "".join(["%02X" % x for x in ti.abtUid[:ti.uiUidLen]])
		if ti.uiAtsLen:
			self.atr = "".join(["%02X" % x for x in ti.abtAts[:ti.uiAtsLen]])
		else:
			self.atr = ""
	
	def __str__(self):
		rv = "ISO14443A(uid='%s', atr='%s')" % (self.uid, self.atr)
		return rv

class ISO14443B(object):
	def __init__(self, ti):
		self.pupi = "".join(["%02X" % x for x in ti.abtPupi[:4]])
		self.uid = self.pupi # for sake of compatibility with apps written for typeA
		self.appdata= "".join(["%02X" % x for x in ti.abtApplicationData[:4]])
		self.protocol= "".join(["%02X" % x for x in ti.abtProtocolInfo[:3]])
		self.cid= "%02x" % ti.ui8CardIdentifier
		self.atr = ""        # idem
	def __str__(self):
		rv = "ISO14443B(pupi='%s')" % (self.pupi)
		return rv

class NFC(object):
	def __init__(self, nfcreader):
		self.LIB = ctypes.util.find_library('nfc')
		#self.LIB = "/usr/local/lib/libnfc.so"
		#self.LIB = "/usr/local/lib/libnfc_26102009.so.0.0.0"
		#self.LIB = "./libnfc_nvd.so.0.0.0"
		#self.LIB = "./libnfc_26102009.so.0.0.0"		
		#self.LIB = "/data/RFID/libnfc/libnfc-svn-1.3.0/src/lib/.libs/libnfc.so"		
		self.device = None
		self.context = ctypes.POINTER(ctypes.c_int)()
		self.poweredUp = False

		self.initLog()
		self.LIBNFC_VER= self.initlibnfc()
		if rfidiotglobals.Debug:
			self.log.debug("libnfc %s" % self.LIBNFC_VER)
		self.configure(nfcreader)
	
	def __del__(self):
		self.deconfigure()

	def initLog(self, level=logging.DEBUG):
#	def initLog(self, level=logging.INFO):
		self.log = logging.getLogger("pynfc")
		self.log.setLevel(level)
		sh = logging.StreamHandler()
		sh.setLevel(level)
		f = logging.Formatter("%(asctime)s: %(levelname)s - %(message)s")
		sh.setFormatter(f)
		self.log.addHandler(sh)

	def initlibnfc(self):
		if rfidiotglobals.Debug:
			self.log.debug("Loading %s" % self.LIB)
		self.libnfc = ctypes.CDLL(self.LIB)
		self.libnfc.nfc_version.restype = ctypes.c_char_p
		self.libnfc.nfc_device_get_name.restype = ctypes.c_char_p
		self.libnfc.nfc_device_get_name.argtypes = [ctypes.c_void_p]
		self.libnfc.nfc_open.restype = ctypes.c_void_p
		self.libnfc.nfc_initiator_init.argtypes = [ctypes.c_void_p]
		self.libnfc.nfc_device_set_property_bool.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_bool];
		self.libnfc.nfc_close.argtypes = [ctypes.c_void_p]
		self.libnfc.nfc_initiator_list_passive_targets.argtypes = [ctypes.c_void_p, ctypes.Structure, ctypes.c_void_p, ctypes.c_size_t]
		self.libnfc.nfc_initiator_transceive_bytes.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32]
		self.libnfc.nfc_init(ctypes.byref(self.context))
		return self.libnfc.nfc_version()

	def listreaders(self, target):
		devices = NFC_DEVICE_LIST()
		nfc_num_devices = ctypes.c_size_t()
		nfc_num_devices= self.libnfc.nfc_list_devices(self.context,ctypes.byref(devices),MAX_DEVICES)
		if target != None:
			if target > nfc_num_devices - 1:
				print 'Reader number %d not found!' % target
				return None
			return devices[target]
		print 'LibNFC ver' , self.libnfc.nfc_version(), 'devices (%d):' % nfc_num_devices
		if nfc_num_devices == 0:
			print '\t', 'no supported devices!'
			return
		for i in range(nfc_num_devices):
			if devices[i]:
				dev = self.libnfc.nfc_open(self.context, ctypes.byref(devices[i]))
				devname= self.libnfc.nfc_device_get_name(dev)
				print '    No: %d\t\t%s' % (i,devname)
				self.libnfc.nfc_close(dev)
				#print '    No: %d\t\t%s (%s)' % (i,devname,devices[i].acDevice)
				#print '    \t\t\t\tDriver:',devices[i].pcDriver
				#if devices[i].pcPort != None:
				#	print '    \t\t\t\tPort:', devices[i].pcPort
				#	print '    \t\t\t\tSpeed:', devices[i].uiSpeed


	def configure(self, nfcreader):
		if rfidiotglobals.Debug:
			self.log.debug("NFC Readers:")
			self.listreaders(None)
			self.log.debug("Connecting to NFC reader number: %s" % repr(nfcreader)) # nfcreader may be none
		if nfcreader != None:
			target=  self.listreaders(nfcreader)
		else:
			target= None 
		if target:
			target= ctypes.byref(target)
		self.device = self.libnfc.nfc_open(self.context, target)
		self.LIBNFC_READER= self.libnfc.nfc_device_get_name(self.device)
		if rfidiotglobals.Debug:
			if self.device == None:
				self.log.error("Error opening NFC reader")
			else:
				self.log.debug("Opened NFC reader " + self.LIBNFC_READER)	
			self.log.debug("Initing NFC reader")
		self.libnfc.nfc_initiator_init(self.device)		
		if rfidiotglobals.Debug:
			self.log.debug("Configuring NFC reader")

  		# Drop the field for a while
		self.libnfc.nfc_device_set_property_bool(self.device,NP_ACTIVATE_FIELD,False);
  	
  		# Let the reader only try once to find a tag
  		self.libnfc.nfc_device_set_property_bool(self.device,NP_INFINITE_SELECT,False);
  		self.libnfc.nfc_device_set_property_bool(self.device,NP_HANDLE_CRC,True);
		self.libnfc.nfc_device_set_property_bool(self.device,NP_HANDLE_PARITY,True);
		self.libnfc.nfc_device_set_property_bool(self.device,NP_ACCEPT_INVALID_FRAMES, True);
  		# Enable field so more power consuming cards can power themselves up
  		self.libnfc.nfc_device_set_property_bool(self.device,NP_ACTIVATE_FIELD,True);

		
	def deconfigure(self):
		if self.device != None:
			if rfidiotglobals.Debug:
				self.log.debug("Deconfiguring NFC reader")
			#self.powerOff()
			self.libnfc.nfc_close(self.device)
			self.libnfc.nfc_exit(self.context)
			if rfidiotglobals.Debug:
				self.log.debug("Disconnected NFC reader")
			self.device = None
			self.context = ctypes.POINTER(ctypes.c_int)()
	
	def powerOn(self):
		self.libnfc.nfc_device_set_property_bool(self.device, NP_ACTIVATE_FIELD, True)
		if rfidiotglobals.Debug:
			self.log.debug("Powered up field")
		self.poweredUp = True
	
	def powerOff(self):
		self.libnfc.nfc_device_set_property_bool(self.device, NP_ACTIVATE_FIELD, False)
		if rfidiotglobals.Debug:
			self.log.debug("Powered down field")
		self.poweredUp = False
	
	def selectISO14443A(self):
		"""Detect and initialise an ISO14443A card, returns an ISO14443A() object."""
		if rfidiotglobals.Debug:
			self.log.debug("Polling for ISO14443A cards")
		#r = self.libnfc.nfc_initiator_select_tag(self.device, IM_ISO14443A_106, None, None, ctypes.byref(ti))
		#r = self.libnfc.nfc_initiator_init(self.device)
		#if RFIDIOtconfig.debug:
		#	self.log.debug('card Select r: ' + str(r))
		#if r == None or r < 0:
		#	if RFIDIOtconfig.debug:
		#		self.log.error("No cards found, trying again")
		#	time.sleep(1)
		#	result = self.readISO14443A()
		#	return result
		#else:
		#	if RFIDIOtconfig.debug:
		#		self.log.debug("Card found")
		self.powerOff()
		self.powerOn()
		nm= NFC_MODULATION()
		target= (NFC_TARGET * MAX_TARGET_COUNT) ()
		nm.nmt = NMT_ISO14443A
		nm.nbr = NBR_106
		if self.libnfc.nfc_initiator_list_passive_targets(self.device, nm, ctypes.byref(target), MAX_TARGET_COUNT):
			return ISO14443A(target[0].nti.nai)
		return None

	def selectISO14443B(self):
		"""Detect and initialise an ISO14443B card, returns an ISO14443B() object."""
		if rfidiotglobals.Debug:
			self.log.debug("Polling for ISO14443B cards")
		self.powerOff()
		self.powerOn()
		nm= NFC_MODULATION()
		target= (NFC_TARGET * MAX_TARGET_COUNT) ()
		nm.nmt = NMT_ISO14443B
		nm.nbr = NBR_106
		if self.libnfc.nfc_initiator_list_passive_targets(self.device, nm, ctypes.byref(target), MAX_TARGET_COUNT):
			return ISO14443B(target[0].nti.nbi)
		return None

	# set Mifare specific parameters
	def configMifare(self):
		self.libnfc.nfc_device_set_property_bool(self.device, NP_AUTO_ISO14443_4, False)
		self.libnfc.nfc_device_set_property_bool(self.device, NP_EASY_FRAMING, True)
		self.selectISO14443A()

	def sendAPDU(self, apdu):
		apdu= "".join([x for x in apdu])
		txData = []		
		for i in range(0, len(apdu), 2):
			txData.append(int(apdu[i:i+2], 16))
	
		txAPDU = ctypes.c_ubyte * len(txData)
		tx = txAPDU(*txData)

		rxAPDU = ctypes.c_ubyte * MAX_FRAME_LEN
		rx = rxAPDU()
	
		if rfidiotglobals.Debug:	
			self.log.debug("Sending %d byte APDU: %s" % (len(tx),"".join(["%02x" % x for x in tx])))
		rxlen = self.libnfc.nfc_initiator_transceive_bytes(self.device, ctypes.byref(tx), ctypes.c_size_t(len(tx)), ctypes.byref(rx), ctypes.c_size_t(len(rx)), -1)
		if rfidiotglobals.Debug:
			self.log.debug('APDU rxlen = ' + str(rxlen))
		if rxlen < 0:
			if rfidiotglobals.Debug:
				self.log.error("Error sending/receiving APDU")
			return False, rxlen
		else:
			rxAPDU = "".join(["%02x" % x for x in rx[:rxlen]])
			if rfidiotglobals.Debug:
				self.log.debug("Received %d byte APDU: %s" % (rxlen, rxAPDU))
			return True, string.upper(rxAPDU)

if __name__ == "__main__":
	n = NFC()
	n.powerOn()
	c = n.readISO14443A()
	print 'UID: ' + c.uid
	print 'ATR: ' + c.atr

	cont = True
	while cont:
		apdu = raw_input("enter the apdu to send now:")
		if apdu == 'exit':
			cont = False
		else:
			r = n.sendAPDU(apdu)
			print r

	print 'Ending now ...'
	n.deconfigure()
