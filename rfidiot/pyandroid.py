#!/usr/bin/python

#
# pyandroid.py - Python code for working with Android NFC reader
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

import binascii
import logging
import time
import readline
import socket
import rfidiotglobals

# listening port
PORT = 4444

class Android(object):
	VERSION = "0.1"
	s = None
	c = None
	
	def __init__(self):
		if rfidiotglobals.Debug:
			self.initLog()
		if rfidiotglobals.Debug:
			self.log.debug("pyandroid starting")
		self.configure()
	
	def __del__(self):
		self.deconfigure()
	
	def deconfigure(self):
		if rfidiotglobals.Debug:
			self.log.debug("pyandroid: deconfiguring")
		if self.c is not None:
				self.c.send("close\n")

	def initLog(self, level=logging.DEBUG):
#	def initLog(self, level=logging.INFO):
		self.log = logging.getLogger("pyandroid")
		self.log.setLevel(level)
		sh = logging.StreamHandler()
		sh.setLevel(level)
		f = logging.Formatter("%(asctime)s: %(levelname)s - %(message)s")
		sh.setFormatter(f)
		self.log.addHandler(sh)

	def configure(self):
		if rfidiotglobals.Debug:
			self.log.debug("pyandroid: Setting up listening port")
		if self.s is not None:
			self.s.close()
		try:
			self.s = socket.socket()         # Create a socket object
			self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self.s.bind(("0.0.0.0", PORT))	# Bind to the port
			self.s.listen(5) 				# Listen for connections
		except Exception as e:
			print 'pyandroid: Could not open port: %s' % PORT
			print e
		
	def reset(self):
		if rfidiotglobals.Debug:
			self.log.debug("pyandroid: Resetting connections")
		if self.c is not None:
			self.c.send("close\n")
			self.c.close()
		if self.s is not None:
			self.s.close()
		self.configure()	
	
	def select(self):
		if rfidiotglobals.Debug:
			self.log.debug("pyandroid in select statement")
		print 'Waiting for connection from Android device ....'
		self.c, addr = self.s.accept()     # Establish connection with client.
		if rfidiotglobals.Debug:
			self.log.debug("pyandroid: Got connection from " + addr[0])
		print "Got connection from ", addr
		# Get UID
		self.c.send('getUID\n')
		uid = self.c.recv(1024)		
		return uid
	
	def sendAPDU(self, apdu):
		if rfidiotglobals.Debug:	
			self.log.debug("Sending APDU: " + apdu)
		self.c.send(apdu + '\n')
		response = self.c.recv(1024)
		response = response[:-1]
		
		if rfidiotglobals.Debug:
			self.log.debug('APDU r =' + response)
		return response

        def sendResults(self, result):
                if rfidiotglobals.Debug:
                        self.log.debug("Sending results: " + results)
                self.c.send('r:' + result + '\n')
                response = self.c.recv(1024)
                response = response[:-1]

                if rfidiotglobals.Debug:
                        self.log.debug('Response r =' + response)
                return response

if __name__ == "__main__":
	n = Android()
	uid = n.select()
	if uid:
		print 'UID: ' + uid
	print

	cont = True
	while cont:
		apdu = raw_input("enter the apdu to send now, send \'close\' to finish :")
		if apdu == 'close':
			cont = False
		else:
			r = n.sendAPDU(apdu)
			print r

	print 'Ending now ...'
	n.deconfigure()
