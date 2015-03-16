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
from ChAPlibVISA import * 

#defines for CVV generation technique
DCVV = 0
CVN17 = 1
FDDA0 = 2
FDDA1 = 3

#setup for CVV generation
#DCVV = 
#CVN17 = 9F02, 9F37, 9F36, 9F10, amount, UN, ATC, Issuer app data.
#FDDA0
#FDD1

#hardcoded list of values for a transaction

TRANS_VALS= {
       0x9f02:[0x00,0x00,0x00,0x00,0x00,0x01],
       0x9f03:[0x00,0x00,0x00,0x00,0x00,0x00],
       0x9f1a:[0x08,0x26],
       0x95:[0x00,0x00,0x00,0x00,0x00],
       0x5f2a:[0x08,0x26],
       0x9a:[0x08,0x04,0x01],
       0x9c:[0x01],
       0x9f37:[0xba,0xdf,0x00,0x0d],
       0x9f66:[0xD7,0x20,0xC0,0x00]   #TTQ    
}

def printpaywavehelp():
    print '\nChAP-paywave.py - Chip And PIN in Python, paywave edition'
    print 'Ver 0.1c\n'
    print 'usage:\n\n ChAP.py [options] [PIN]'
    print
    print 'If the optional numeric PIN argument is given, the PIN will be verified (note that this' 
    print 'updates the PIN Try Counter and may result in the card being PIN blocked).'
    print '\nOptions:\n'
    print '\t-a\t\tBruteforce AIDs'
    print '\t-A\t\tPrint list of known AIDs'
    print '\t-d\t\tDebug - Show PC/SC APDU data'
    print '\t-h\t\tPrint detailed help message'
    print '\t-o\t\tOutput to files ([AID]-FILExxRECORDxx.HEX)'
    print '\t-r\t\tRaw output - do not interpret EMV data'
    print '\t-t\t\tUse T1 protocol (default is T0)'
    print '\t-v\t\tVerbose on'
    print '\t-C\t\tCVV generation mode (dCVV, CVN17, fDDA0, fDDA1)'
    print '\t-R\t\tUnpredictable Number' 
    print


try:
    # 'args' will be set to remaining arguments (if any)
    UN = list()
    countrycode = list() 
    opts, args  = getopt.getopt(sys.argv[1:],'aAdefoprtvC:R:c:')
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
        if o == '-C':
            if a == 'dCVV':
                CVV = DCVV 
            elif a == 'CVN17':
                CVV = CVN17 
            elif a == 'fDDA0':        
                CVV = FDDA0 
            elif a == 'fDDA1':        
                CVV = FDDA1
        if o == '-R':
            UNstring = "%08x"%int(a)
            UN.append(int(UNstring[0:2]))
            UN.append(int(UNstring[2:4]))
            UN.append(int(UNstring[4:6]))
            UN.append(int(UNstring[6:8]))
        if o == '-c':
            #country code
            ccstring = "%04x"%int(a)
            countrycode.append(int(ccstring[0:2]))
            countrycode.append(int(ccstring[2:4])) 
             
except getopt.GetoptError:
    # -h will cause an exception as it doesn't exist!
    printpaywavehelp()
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

    # try to select PSE
    apdu = SELECT + [len(DF_PSE)] + DF_PSE + [0x00]
    response, sw1, sw2 = send_apdu( apdu, cardservice )

    if check_return(sw1,sw2):
        # there is a PSE
        print 'PSE found!'
        decode_pse(response)
        #get the returned AID 
        status, length, AID = get_tag(response,0x4F)
        print 'Selecting AID from card' 
        status, response, sw1, sw2 = select_aid(AID, cardservice) 
        status, length, pdol = get_tag(response,0x9F38)
        print 'Processing Data Options List='
        decode_DOL(pdol)      
        #get processing options 
        if CVV == DCVV:
            TRANS_VALS[0x9f66] = [0x80, 0x00, 0x00, 0x00] #MSD required, no cryptogram
        elif CVV == CVN17:
            TRANS_VALS[0x9f66] = [0x80, 0x80, 0x00, 0x00] #MSD, with cryptogram
        elif CVV == FDDA0:
            TRANS_VALS[0x9f66] = [0x20, 0x80, 0x00, 0x00]  #qVSDC
        elif CVV == FDDA0:
            TRANS_VALS[0x9f66] = [0xB7, 0x80, 0x00, 0x00]
        if len(UN) > 0:
            TRANS_VALS[0x9F37] = [UN[0],UN[1],UN[2],UN[3]]
        if len(countrycode) > 0:
            TRANS_VALS[0x9F1A] = [countrycode[0], countrycode[1]]
            TRANS_VALS[0x5f2a] = [countrycode[0], countrycode[1]]
         
        #generate list of PDOL tags from response 
        pdollist = list() 
        x = 0
        while x < (len(pdol)): 
            tagstart = x 
            x += 1
            if (pdol[x] & TLV_TAG_NUMBER_MASK) == TLV_TAG_NUMBER_MASK:
                x += 1
                while pdol[x] & TLV_TAG_MASK:
                    x += 1
            x += 1
            taglen = x 
            tag = pdol[tagstart:taglen]  
            #tags = map(hex, tag)
            tags = ["{0:02X}".format(item) for item in tag]
            tags = ''.join(tags)
            tags = int(tags,16) 
            pdollist.append(tags) 
            x += 1
        status, response = get_processing_options(pdollist,TRANS_VALS, cardservice)
        decode_processing_options(response, cardservice) 
        if CVV == CVN17 | CVV == FDDA0 | CVV == FDDA1:
            status,length,CTQdata = get_tag(response,0x9f06)     
            print decodeCTQ(CTQdata)
        #bruteforce_files(cardservice) 
        #get_UNSize() 
    else:
        print 'no PSE: %02x %02x' % (sw1,sw2)

except CardRequestTimeoutException:
    print 'time-out: no card inserted during last 10s'

if 'win32'==sys.platform:
    print 'press Enter to continue'
    sys.stdin.read(1)
