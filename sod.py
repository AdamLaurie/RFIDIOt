#!/usr/bin/python


#  sod.py - try to find X509 data in EF.SOD
# 
#  Adam Laurie <adam@algroup.co.uk>
#  http://rfidiot.org/
# 
#  This code is copyright (c) Adam Laurie, 2007, All rights reserved.
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
import commands
import sys
import os

x= 0
if len(sys.argv) > 1:
	sod= open(sys.argv[1],"r")
else:
	sod= open("/tmp/EF_SOD.BIN","r")
data= sod.read()
while x < len(data):
	out= open("/tmp/SOD","w")
	out.write(data[x:])
	out.flush()
	out.close()
	(exitstatus, outtext) = commands.getstatusoutput("openssl pkcs7 -text -print_certs -in /tmp/SOD -inform DER")
	if not exitstatus and len(outtext) > 0:
		print 'PKCS7 certificate found at offset %d:' % x
		print
		print outtext
		os._exit(False)
	x += 1
os._exit(True)
