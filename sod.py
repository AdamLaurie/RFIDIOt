#!/usr/bin/python3
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
import sys
import subprocess
# import os

x = 0
if len(sys.argv) > 1:
    sod = open(sys.argv[1], "r", encoding="utf-8")
else:
    sod = open("/tmp/EF_SOD.BIN", "r", encoding="utf-8")
data = sod.read()
while x < len(data):
    with open("/tmp/SOD", "w", encoding="utf-8") as fd:
        fd.write(data[x:])
    (exitstatus, outtext) = subprocess.getstatusoutput("openssl pkcs7 -text -print_certs -in /tmp/SOD -inform DER")
    if not exitstatus and len(outtext) > 0:
        print("PKCS7 certificate found at offset %d:" % x)
        print()
        print(outtext)
        sys.exit(False)
    x += 1
sys.exit(True)
