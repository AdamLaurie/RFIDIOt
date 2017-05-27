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
from smartcard.Exceptions import CardConnectionException
import getopt
import sys
from operator import *
# local imports
from rfidiot.iso3166 import ISO3166CountryCodes
from ChAPlib import * 

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
while 1:    
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
    
        # try to select PSE
        apdu = SELECT + [len(DF_PSE)] + DF_PSE + [0x00]
        response, sw1, sw2 = send_apdu( apdu, cardservice )
        apdu = [0xAA,0xBB,0x00,0x00,0x00]
        try: 
            response, sw1, sw2 = send_apdu( apdu, cardservice )
        except CardConnectionException:
            pass
    except CardRequestTimeoutException:
        print 'time-out: no card inserted during last 10s'
    
if 'win32'==sys.platform:
    print 'press Enter to continue'
    sys.stdin.read(1)
