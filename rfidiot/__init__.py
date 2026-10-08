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


import getopt
import sys
import os
# import string

from . import rfidiotglobals
from . import RFIDIOt

# help flag (-h) set?
help = False

# nogui flag (-g) set?
nogui = False

# noinit flag (-n) set?
noinit = False

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
# line= "/dev/ttyS0"
# line= "/dev/ttyS1"
line = "/dev/ttyUSB0"
# for Windows
# line= "COM4"

# reader type (can be overridden with -R)
readertype = RFIDIOt.rfidiot.READER_ACG
# readertype= RFIDIOt.rfidiot.READER_FROSCH
# readertype= RFIDIOt.rfidiot.READER_DEMOTAG
# READER_PCSC is a meta type. Actual subtype will be auto-determined.
# readertype= RFIDIOt.rfidiot.READER_PCSC
# readertype= RFIDIOt.rfidiot.READER_NONE
# readertype= RFIDIOt.rfidiot.READER_LIBNFC
# readertype= RFIDIOt.rfidiot.READER_ANDROID

# PCSC reader number (can be overridden with -r)
readernum = 0

# serial port speed (can be overridden with -s)
# ignored for PCSC
speed = 9600
# speed= 57600
# speed= 115200
# speed= 230400
# speed= 460800

# reader timeout (can be overriden with -t)
# ignored for PCSC
timeout = 1

# libnfc reader number (if set to 'None' first available device will be used)
# can be overridden with -f
nfcreader = None


def printoptions():
    print("\nRFIDIOt Options:\n")
    print("\t-d\t\tDebug on")
    print("\t-f <num|conn>\tUse LibNFC device number <num>, or a libnfc connstring such")
    print("\t\t\tas 'pn53x_usb' or 'pn53x_usb:003:087' to open that device")
    print("\t\t\tdirectly without probing (and grabbing) other readers")
    print("\t\t\t(implies -R READER_LIBNFC)")
    print("\t-g\t\tNo GUI")
    print("\t-h\t\tPrint detailed help message")
    print("\t-n\t\tNo Init - do not initialise hardware")
    print("\t-N\t\tList available LibNFC devices")
    print("\t-r <num>\tUse PCSC device number <num> (implies -R READER_PCSC)")
    print("\t-R <type>\tReader/writer type:")
    print("\t\t\t\tREADER_ACG:\tACG Serial")
    print("\t\t\t\tREADER_ACS:\tPC/SC Subtype ACS")
    print("\t\t\t\tREADER_ANDROID:\tAndroid")
    print("\t\t\t\tREADER_CHAMELEON:\tChameleon Ultra (serial, ISO 14443-A reader)")
    print("\t\t\t\tREADER_DEMOTAG:\tDemoTag")
    print("\t\t\t\tREADER_FROSCH:\tFrosch Hitag")
    print("\t\t\t\tREADER_LIBNFC:\tlibnfc")
    print("\t\t\t\tREADER_NONE:\tNone")
    print("\t\t\t\tREADER_OMNIKEY:\tPC/SC Subtype OmniKey")
    print("\t\t\t\tREADER_PCSC:\tPC/SC")
    print("\t\t\t\tREADER_SCM:\tPC/SC Subtype SCM")
    print("\t-l <line>\tLine to use for reader/writer")
    print("\t-L\t\tList available PCSC devices")
    print("\t-s <baud>\tSpeed of reader/writer")
    print("\t-t <seconds>\tTimeout for inactivity of reader/writer")
    print()


# check for global overrides in local config files, in the following order:
#   $(RFIDIOtconfig_opts)
#   ./RFIDIOtconfig.opts
#   /etc/RFIDIOtconfig.opts
# note that command line options will take precedence
extraopts = []
OptsEnv = "RFIDIOtconfig_opts"
if OptsEnv in os.environ:
    try:
        with open(os.environ[OptsEnv], encoding="utf-8") as configfile:
            extraopts = configfile.readline().split()
    except:
        print(
            "*** warning: config file set by ENV not found (%s) or empty!"
            % (os.environ[OptsEnv])
        )
        print("*** not checking for other option files!")
else:
    for path in [".", "/etc"]:
        try:
            with open(path + "/RFIDIOtconfig.opts", encoding="utf-8") as configfile:
                extraopts = configfile.readline().split()
                break
        except:
            pass
# check for global override in environment variable
OptsEnv = "RFIDIOtconfig"
if OptsEnv in os.environ:
    try:
        extraopts = os.environ[OptsEnv].split()
    except:
        print("*** warning: RFIDIOtconfig found in ENV, but no options specified!")
# ignore if commented out
if len(extraopts) > 0:
    if extraopts[0][0] == "#":
        extraopts = []

# RFIDIOt's own global reader options. A client script may define its own
# options on top of these (e.g. ChAP.py); those are not known here, so rather
# than abort on them we parse only the options below and hand everything else
# (unknown options and positional arguments) back to the script in 'args'. This
# lets a tool do a plain 'import rfidiot' and then getopt rfidiot.args itself.
_GLOBAL_OPTS = "df:ghjnNr:R:l:Ls:t:"


def _partition_opts(tokens, optstring):
    "split tokens into our known options (for getopt) and everything else"
    witharg, noarg, i = set(), set(), 0
    while i < len(optstring):
        c = optstring[i]
        if i + 1 < len(optstring) and optstring[i + 1] == ":":
            witharg.add(c)
            i += 2
        else:
            noarg.add(c)
            i += 1
    known, rest, i, n = [], [], 0, len(tokens)
    while i < n:
        t = tokens[i]
        if t == "--":
            rest.extend(tokens[i + 1:])
            break
        if len(t) >= 2 and t[0] == "-" and t[1] != "-":
            j = 1
            while j < len(t):
                c = t[j]
                if c in witharg:
                    arg = t[j + 1:]
                    if arg:
                        known += ["-" + c, arg]
                    elif i + 1 < n:
                        known += ["-" + c, tokens[i + 1]]
                        i += 1
                    else:
                        known.append("-" + c)
                    j = len(t)
                elif c in noarg:
                    known.append("-" + c)
                    j += 1
                else:
                    # not one of ours - hand the rest of the cluster to the script
                    rest.append("-" + t[j:])
                    j = len(t)
            i += 1
        else:
            # first positional argument ends option processing (POSIX-style)
            rest.extend(tokens[i:])
            break
    return known, rest


# set True if global-option parsing fails, so a later 'card' access reports the
# failure (as a missing attribute the caller's guard catches) instead of building
# a reader from half-parsed options
_config_error = False

# 'args' will be set to remaining arguments (if any)
try:
    _known, args = _partition_opts(extraopts + sys.argv[1:], _GLOBAL_OPTS)
    opts, _ = getopt.getopt(_known, _GLOBAL_OPTS)

    for o, a in opts:
        if o == "-j":
            rfidiotglobals.Json = True
            continue
        if o == "-d":
            rfidiotglobals.Debug = True
        if o == "-f":
            # a device number, or a libnfc connstring (e.g. "pn53x_usb") which is
            # opened directly without the intrusive nfc_list_devices probe that
            # would grab other readers (e.g. acr122 devices shared with PC/SC)
            try:
                nfcreader = int(a)
            except ValueError:
                nfcreader = a
            readertype = RFIDIOt.rfidiot.READER_LIBNFC
        if o == "-g":
            nogui = True
        if o == "-h":
            # print the global reader options, flag help, and select no reader
            # so no hardware is touched. Do NOT exit: control returns to the
            # tool, which prints its own help (if any) by checking rfidiot.help
            # and then exits.
            printoptions()
            help = True
            readertype = RFIDIOt.rfidiot.READER_NONE
        if o == "-n":
            noinit = True
        if o == "-N":
            # list libnfc devices without opening one (opening would make
            # nfc_list_devices' intrusive probe fail with EBUSY)
            from .pynfc import NFC

            nfc = NFC(nfcreader, listonly=True)
            nfc.listreaders(None)
            sys.stdout.flush()
            os._exit(True)
        if o == "-r":
            readernum = a
            readertype = RFIDIOt.rfidiot.READER_PCSC
        if o == "-R":
            try:
                readertype = eval(a)
            except:
                readertype = eval("RFIDIOt.rfidiot." + a)
        if o == "-l":
            line = a
        if o == "-L":
            readertype = RFIDIOt.rfidiot.READER_PCSC
            readernum = 0
            card = RFIDIOt.rfidiot(
                readernum,
                readertype,
                line,
                speed,
                timeout,
                rfidiotglobals.Debug,
                noinit,
                nfcreader,
            )
            card.pcsc_listreaders()
            sys.stdout.flush()
            os._exit(True)
        if o == "-s":
            speed = int(a)
        if o == "-t":
            timeout = int(a)
    # NB: the reader is NOT opened here. 'card' is built lazily on first access
    # (see __getattr__ below) so that 'import rfidiot' has no hardware side effect
    # and never exits the process - a GUI or any tool that imports the package
    # without using a reader is no longer killed by an open failure (issue #35).
except getopt.GetoptError as e:
    print("RFIDIOtconfig module ERROR: %s" % e)
    printoptions()
    args = []
    _config_error = True


def __getattr__(name):
    # PEP 562 lazy module attribute. The reader is opened only when a tool first
    # accesses rfidiot.card - which in every tool happens inside its own
    # try/except guard - so importing the package has no hardware side effect and
    # does not exit the process (issue #35). The built instance is cached in the
    # module globals, so subsequent accesses skip this hook.
    if name == "card":
        if _config_error:
            # option parsing failed; behave as before (no usable reader) and let
            # the caller's guard report "Couldn't open reader"
            raise AttributeError("reader not available: global option parsing failed")
        card = RFIDIOt.rfidiot(
            readernum,
            readertype,
            line,
            speed,
            timeout,
            rfidiotglobals.Debug,
            noinit,
            nfcreader,
        )
        # expose the help flag on the card so card.info() can stop after the banner
        card.help = help
        globals()["card"] = card
        return card
    raise AttributeError("module %r has no attribute %r" % (__name__, name))
