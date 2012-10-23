#!/usr/bin/python


#  RFIDIOtconfig.py - shared settings for local RFIDIOt
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

import rfidiotglobals

import RFIDIOt
import getopt
import sys
import os
import string

# help flag (-h) set?
help= False

# nogui flag (-g) set?
nogui= False

# noinit flag (-n) set?
noinit= False

# options specified in this file can be overridden on the command line, or in static
# files as defined below, in the following order:
#   $(RFIDIOtconfig_opts)
#   ./RFIDIOtconfig.opts
#   /etc/RFIDIOtconfig.opts
#
# options can also be specified in the ENV variable $(RFIDIOtconfig)
#
# note that command line options will take precedence

# change the following sections to match your serial port
# bluetooth connections need at least 1 second timeout to establish connection

# serial port (can be overridden with -l)

# ignored for PCSC
#line= "/dev/ttyS0"
#line= "/dev/ttyS1"
line= "/dev/ttyUSB0"
# for Windows
#line= "COM4"

# reader type (can be overridden with -R)
#readertype= RFIDIOt.rfidiot.READER_ACG
#readertype= RFIDIOt.rfidiot.READER_FROSCH
#readertype= RFIDIOt.rfidiot.READER_DEMOTAG
# READER_PCSC is a meta type. Actual subtype will be auto-determined.
readertype= RFIDIOt.rfidiot.READER_PCSC
#readertype= RFIDIOt.rfidiot.READER_NONE
#readertype= RFIDIOt.rfidiot.READER_LIBNFC
#readertype= RFIDIOt.rfidiot.READER_ANDROID

# PCSC reader number (can be overridden with -r)
readernum= 0

# serial port speed (can be overridden with -s)
# ignored for PCSC
speed= 9600
#speed= 57600
#speed= 115200
#speed= 230400
#speed= 460800

# reader timeout (can be overriden with -t)
# ignored for PCSC
timeout= 1

# libnfc reader number (if set to 'None' first available device will be used)
# can be overridden with -f
nfcreader= None

def printoptions():
	print '\nRFIDIOt Options:\n'
	print '\t-d\t\tDebug on'
	print '\t-f <num>\tUse LibNFC device number <num> (implies -R READER_LIBNFC)'
	print '\t-g\t\tNo GUI'
	print '\t-h\t\tPrint detailed help message'
	print '\t-n\t\tNo Init - do not initialise hardware'
	print '\t-N\t\tList available LibNFC devices'
	print '\t-r <num>\tUse PCSC device number <num> (implies -R READER_PCSC)'
	print '\t-R <type>\tReader/writer type:'
	print '\t\t\t\tREADER_ACG:\tACG Serial'
	print '\t\t\t\tREADER_ACS:\tPC/SC Subtype ACS'
	print '\t\t\t\tREADER_ANDROID:\tAndroid'
	print '\t\t\t\tREADER_DEMOTAG:\tDemoTag'
	print '\t\t\t\tREADER_FROSCH:\tFrosch Hitag'
	print '\t\t\t\tREADER_LIBNFC:\tlibnfc'
	print '\t\t\t\tREADER_NONE:\tNone'
	print '\t\t\t\tREADER_OMNIKEY:\tPC/SC Subtype OmniKey'
	print '\t\t\t\tREADER_PCSC:\tPC/SC'
	print '\t\t\t\tREADER_SCM:\tPC/SC Subtype SCM'
	print '\t-l <line>\tLine to use for reader/writer'
	print '\t-L\t\tList available PCSC devices'
	print '\t-s <baud>\tSpeed of reader/writer'
	print '\t-t <seconds>\tTimeout for inactivity of reader/writer'
	print

# check for global overrides in local config files, in the following order:
#   $(RFIDIOtconfig_opts)
#   ./RFIDIOtconfig.opts
#   /etc/RFIDIOtconfig.opts
# note that command line options will take precedence
extraopts= []
OptsEnv= 'RFIDIOtconfig_opts'
if os.environ.has_key(OptsEnv):
	try:
		configfile= open(os.environ[OptsEnv])
		extraopts= string.split(configfile.read())
	except:
    		print "*** warning: config file set by ENV not found (%s) or empty!" % (os.environ[OptsEnv])
		print "*** not checking for other option files!"
else:
	for path in ['.','/etc']:
		try:
			configfile= open(path + '/RFIDIOtconfig.opts')
			extraopts= string.split(configfile.read())
			break
		except:
			pass
# check for global override in environment variable
OptsEnv= 'RFIDIOtconfig'
if os.environ.has_key(OptsEnv):
	try:	
		extraopts= string.split(os.environ[OptsEnv])
	except:
		print "*** warning: RFIDIOtconfig found in ENV, but no options specified!"
# ignore if commented out
if len(extraopts) > 0:
	if extraopts[0][0] == '#':
		extraopts= [] 

# 'args' will be set to remaining arguments (if any)
try:
	opts, args  = getopt.getopt(extraopts + sys.argv[1:],'df:ghnNr:R:l:Ls:t:')

	for o, a in opts:
		if o == '-d':
			rfidiotglobals.Debug= True
		if o == '-f':
			nfcreader= int(a)
			readertype= RFIDIOt.rfidiot.READER_LIBNFC
		if o == '-g':
			nogui= True
		if o == '-h':
			help= True
			printoptions()
		if o == '-n':
			noinit= True
		if o == '-N':
			readertype= RFIDIOt.rfidiot.READER_LIBNFC
			card= RFIDIOt.rfidiot(readernum,readertype,line,speed,timeout,rfidiotglobals.Debug,noinit,nfcreader)
			card.libnfc_listreaders()
			os._exit(True)
		if o == '-r':
			readernum= a
			readertype= RFIDIOt.rfidiot.READER_PCSC
		if o == '-R':
			try:
				readertype= eval(a)
			except:
				readertype= eval('RFIDIOt.rfidiot.'+a)
		if o == '-l':
			line= a
		if o == '-L':
			readertype= RFIDIOt.rfidiot.READER_PCSC
			readernum= 0
			card= RFIDIOt.rfidiot(readernum,readertype,line,speed,timeout,rfidiotglobals.Debug,noinit,nfcreader)
			card.pcsc_listreaders()
			os._exit(True)
		if o == '-s':
			speed= int(a)
		if o == '-t':
			timeout= int(a)
	card= RFIDIOt.rfidiot(readernum,readertype,line,speed,timeout,rfidiotglobals.Debug,noinit,nfcreader)
except getopt.GetoptError,e:
   		print "RFIDIOtconfig module ERROR: %s" % e
		printoptions()
		args= []
