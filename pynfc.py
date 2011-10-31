#!/usr/bin/python

#
# pynfc.py - Python wrapper for libnfc
# version 0.2 (should work with libnfc 1.2.1 and 1.3.0)
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

from ctypes import *
import binascii
import logging
import time
import readline
import RFIDIOtconfig

DCO_HANDLE_CRC              = 0x00
DCO_HANDLE_PARITY           = 0x01
DCO_ACTIVATE_FIELD          = 0x10
DCO_INFINITE_LIST_PASSIVE   = 0x20
DCO_INFINITE_SELECT         = 0x20
DCO_ACCEPT_INVALID_FRAMES   = 0x30
DCO_ACCEPT_MULTIPLE_FRAMES  = 0x31

IM_ISO14443A_106  = 0x00
IM_FELICA_212     = 0x01
IM_FELICA_424     = 0x02
IM_ISO14443B_106  = 0x03
IM_JEWEL_106      = 0x04

MAX_FRAME_LEN = 264
MAX_DEVICES = 16
BUFSIZ = 8192

class TAG_INFO_ISO14443A(Structure):
	_fields_ = [('abtAtqa', c_ubyte * 2),
		    ('btSak', c_ubyte),
		    ('uiUidLen', c_ulong),
		    ('abtUid', c_ubyte * 10),
		    ('uiAtsLen', c_ulong),
		    ('abtAts', c_ubyte * 36)]

class NFC_DEVICE_DESC_T(Structure):
	_fields_ = [('acDevice',c_char * BUFSIZ),
		    ('pcDriver',c_char_p),
		    ('pcPort',c_char_p),
		    ('uiSpeed',c_ulong),
		    ('uiBusIndex',c_ulong)]

NFC_DEVICE_LIST = NFC_DEVICE_DESC_T * MAX_DEVICES

class ISO14443A(object):
	def __init__(self, ti):
		self.uid = "".join(["%02x" % x for x in ti.abtUid[:ti.uiUidLen]])
		if ti.uiAtsLen:
			self.atr = "".join(["%02x" % x for x in ti.abtAts[:ti.uiAtsLen]])
		else:
			self.atr = ""
	
	def __str__(self):
		rv = "ISO14443A(uid='%s', atr='%s')" % (self.uid, self.atr)
		return rv

class NFC(object):

	def __init__(self):
		self.LIB = "/usr/local/lib/libnfc.so"
		#self.LIB = "/usr/local/lib/libnfc_26102009.so.0.0.0"
		#self.LIB = "./libnfc_nvd.so.0.0.0"
		#self.LIB = "./libnfc_26102009.so.0.0.0"		
		#self.LIB = "/data/RFID/libnfc/libnfc-svn-1.3.0/src/lib/.libs/libnfc.so"		
		self.device = None
		self.poweredUp = False

		if RFIDIOtconfig.debug:
			self.initLog()
		self.LIBNFC_VER= self.initlibnfc()
		if RFIDIOtconfig.debug:
			self.log.debug("libnfc %s" % self.LIBNFC_VER)
		self.configure()
	
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
		if RFIDIOtconfig.debug:
			self.log.debug("Loading %s" % self.LIB)
		self.libnfc = CDLL(self.LIB)
		self.libnfc.nfc_version.restype = c_char_p
		return self.libnfc.nfc_version()

	def listreaders(self, target):
		devices = NFC_DEVICE_LIST()
		nfc_num_devices = c_ulong()
		self.libnfc.nfc_list_devices(byref(devices),MAX_DEVICES,byref(nfc_num_devices))
		if target != None:
			if nfc_num_devices.value <= target:
				print 'Reader number %d not found!' % target
				return None
			i=  0
			for dev in devices:
				if i == target:
					return dev
				i= i + 1
		print 'LibNFC ver' , self.libnfc.nfc_version(), 'devices:'
		if nfc_num_devices.value == 0:
			print '\t', 'no supported devices!'
			return
		i= 0
		for dev in devices:
			if dev.acDevice:
				print '    No: %d\t\t%s' % (i,dev.acDevice)
				print '    \t\t\t\tDriver:',dev.pcDriver
				if dev.pcPort != None:
					print '    \t\t\t\tPort:', dev.pcPort
					print '    \t\t\t\tSpeed:', dev.uiSpeed
				i = i + 1

	def configure(self):
		if RFIDIOtconfig.debug:
			self.log.debug("NFC Readers:")
			self.listreaders(None)
			self.log.debug("Connecting to NFC reader")
		if RFIDIOtconfig.nfcreader:
			target=  self.listreaders(RFIDIOtconfig.nfcreader)
		else:
			target= None 
		if target:
			target= byref(target)
		self.device = self.libnfc.nfc_connect(target)
		self.libnfc.nfc_device_name.restype = c_char_p
		self.LIBNFC_READER= self.libnfc.nfc_device_name(self.device)	
		if RFIDIOtconfig.debug:
			if self.device == None:
				self.log.error("Error opening NFC reader")
			else:
				self.log.debug("Opened NFC reader " + self.LIBNFC_READER)	
			self.log.debug("Initing NFC reader")
		self.libnfc.nfc_initiator_init(self.device)		
		if RFIDIOtconfig.debug:
			self.log.debug("Configuring NFC reader")

  		# Drop the field for a while
		self.libnfc.nfc_configure(self.device,DCO_ACTIVATE_FIELD,False);
  	
  		# Let the reader only try once to find a tag
  		self.libnfc.nfc_configure(self.device,DCO_INFINITE_SELECT,False);
  		self.libnfc.nfc_configure(self.device,DCO_HANDLE_CRC,True);
		self.libnfc.nfc_configure(self.device,DCO_HANDLE_PARITY,True);
		self.libnfc.nfc_configure(self.device,DCO_ACCEPT_INVALID_FRAMES, True);
  		# Enable field so more power consuming cards can power themselves up
  		self.libnfc.nfc_configure(self.device,DCO_ACTIVATE_FIELD,True);
		
	def deconfigure(self):
		if self.device != None:
			if RFIDIOtconfig.debug:
				self.log.debug("Deconfiguring NFC reader")
			#self.powerOff()
			self.libnfc.nfc_disconnect(self.device)
			if RFIDIOtconfig.debug:
				self.log.debug("Disconnected NFC reader")
			self.device == None
	
	def powerOn(self):
		self.libnfc.nfc_configure(self.device, DCO_ACTIVATE_FIELD, True)
		if RFIDIOtconfig.debug:
			self.log.debug("Powered up field")
		self.poweredUp = True
	
	def powerOff(self):
		self.libnfc.nfc_configure(self.device, DCO_ACTIVATE_FIELD, False)
		if RFIDIOtconfig.debug:
			self.log.debug("Powered down field")
		self.poweredUp = False
	
	def readISO14443A(self):
		"""Detect and read an ISO14443A card, returns an ISO14443A() object."""
		if RFIDIOtconfig.debug:
			self.log.debug("Polling for ISO14443A cards")
		ti = TAG_INFO_ISO14443A()
		r = self.libnfc.nfc_initiator_select_tag(self.device, IM_ISO14443A_106, None, None, byref(ti))
		if RFIDIOtconfig.debug:
			self.log.debug('card Select r: ' + str(r))
		if r == None or r ==0:
			if RFIDIOtconfig.debug:
				self.log.error("No cards found, trying again")
			time.sleep(1)
			result = self.readISO14443A()
			return result
		else:
			if RFIDIOtconfig.debug:
				self.log.debug("Card found")
			return ISO14443A(ti)

	def sendAPDU(self, apdu):
		txData = []		
		for i in range(0, len(apdu), 2):
			txData.append(int(apdu[i:i+2], 16))
	
		txAPDU = c_ubyte * len(txData)
		tx = txAPDU(*txData)

		rxAPDU = c_ubyte * MAX_FRAME_LEN
		rx = rxAPDU()
		rxlen = c_ulong()

	
		if RFIDIOtconfig.debug:	
			self.log.debug("Sending %d byte APDU: %s" % (len(tx),"".join(["%02x" % x for x in tx])))
		r = self.libnfc.nfc_initiator_transceive_dep_bytes(self.device, byref(tx), c_ulong(len(tx)), byref(rx), byref(rxlen))		
		if RFIDIOtconfig.debug:
			self.log.debug('APDU r =' + str(r))
		if r == 0:
			if RFIDIOtconfig.debug:
				self.log.error("Error sending/recieving APDU")

			result = False
			return result
		else:
			rxAPDU = "".join(["%02x" % x for x in rx[:rxlen.value]])
			if RFIDIOtconfig.debug:
				self.log.debug("Recieved %d byte APDU: %s" % (rxlen.value, rxAPDU))
			return rxAPDU

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
