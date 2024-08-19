#!/usr/bin/python3
#  pn532mitm.py - NXP PN532 Man-In-The_Middle - log conversations between TAG and external reader
#
#  Adam Laurie <adam@algroup.co.uk>
#  http://rfidiot.org/
#
#  This code is copyright (c) Adam Laurie, 2009, All rights reserved.
#  For non-commercial use only, the following terms apply - for all other
#  uses, please contact the author:
#
#    This code is free software; you can redi!tribute it and/or modify
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
import os
# import string
import socket
import time
import random
# import operator
import rfidiot
from rfidiot.pn532 import *


# try to connect to remote host. if that fails, alternately listen and connect.
def connect_to(chost, cport, ctype):
    print("host", chost, "port", cport, "type", ctype)
    peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    random.seed()
    first = True
    while 42:
        peer.settimeout(random.randint(1, 10))
        print("  Paging {chost} {cport}                    \r", end="")
        sys.stdout.flush()
        time.sleep(1)
        try:
            if peer.connect((chost, cport)) == 0:
                print("  Connected to {chost}s cport {port}                  ")
                send_data(peer, ctype)
                cdata = recv_data(peer)
                connection = peer
                break
        except Exception as exc:
            # connection refused - the other end isn't up yet
            if exc.errno == 111:
                pass
            else:
                print("Could not open local socket:                    ")
                print(exc)
                sys.exit(True)
        try:
            print("  Listening for REMOTE on cport %s              \r" % port, end="")
            sys.stdout.flush()
            if first:
                peer.bind(("0.0.0.0", cport))
                peer.listen(1)
                first = False
            conn, addr = peer.accept()
            if conn:
                print("  Connected to %s cport %d                  " % (addr[0], addr[1]))
                cdata = recv_data(conn)
                send_data(conn, ctype)
                connection = conn
                break
        except socket.timeout:
            pass
    if cdata == ctype:
        print("  Handshake failed - both ends are set to", ctype)
        time.sleep(1)
        connection.close()
        sys.exit(True)
    print("  Remote is", cdata)
    print()
    return connection


# send data with 3 digit length and 2 digit CRC
def send_data(chost, cdata):
    lrc = 0
    length = "%03x" % (len(cdata) + 2)
    for i in length + data:
        lrc ^=  ord(i)
        # lrc = operator.xor(lrc, ord(x))
    chost.send(length)
    chost.send(cdata)
    chost.send("%02x" % lrc)


# receive data of specified length and check CRC
def recv_data(chost):
    out = ""
    while len(out) < 3:
        out += chost.recv(3 - len(out))
    length = int(out, 16)
    lrc = 0
    for x in out:
        # lrc = operator.xor(lrc, ord(x))
        lrc ^=  ord(x)
    out = ""
    while len(out) < length:
        out += chost.recv(length - len(out))
    for x in out[:-2]:
        # lrc = operator.xor(lrc, ord(x))
        lrc ^=  ord(x)
    if lrc != int(out[-2:], 16):
        print("  Remote socket CRC failed!")
        chost.close()
        sys.exit(True)
    return out[:-2]


try:
    card = rfidiot.card
except:
    sys.exit(True)

args = rfidiot.args
chelp = rfidiot.help

card.info("pn532mitm v0.1e")

if chelp or len(args) < 1:
    print(sys.argv[0] + " - NXP PN532 Man-In-The-Middle")
    print()
    print("\tUsage: " + sys.argv[0] + " <EMULATOR|REMOTE> [LOG FILE] ['QUIET']")
    print()
    print("\t  Default PCSC reader will be the READER. Specify reader number to use as an EMULATOR as")
    print("\t  the <EMULATOR> argument.")
    print()
    print("\t  To utilise a REMOTE device, use a string in the form 'emulator:HOST:PORT' or 'reader:HOST:PORT'.")
    print()
    print("\t  COMMANDS and RESPONSES will be relayed between the READER and the EMULATOR, and relayed")
    print("\t  traffic will be displayed (and logged if [LOG FILE] is specified).")
    print()
    print("\t  If the 'QUIET' option is specified, traffic log will not be displayed on screen.")
    print()
    print("\t  Logging is in the format:")
    print()
    print("\t    << DATA...        - HEX APDU received by EMULATOR and relayed to READER")
    print("\t    >> DATA... SW1SW2 - HEX response and STATUS received by READER and relayed to EMULATOR")
    print()
    print("\t  Examples:")
    print()
    print("\t    Use device no. 2 as the READER and device no. 3 as the EMULATOR:")
    print()
    print("\t      " + sys.argv[0] + " -r 2 3")
    print()
    print("\t    Use device no. 2 as the EMULATOR and remote system on 192.168.1.3 port 5000 as the READER:")
    print()
    print("\t      " + sys.argv[0] + " -r 2 reader:192.168.1.3:5000")
    print()
    sys.exit(True)

# logging = False
logfile = None
if len(args) > 1:
    if os.path.isfile(args[1]):
        x = input("  *** Warning! File already exists! Overwrite (y/n)? ").upper()
        if x != "Y":
            sys.exit(True)

    try:
        logfile = open(args[1], "w", encoding="utf-8" )
        # logging = True
    except Exception as _e:
        print("  Couldn't create logfile:", args[1])
        print("  {_e}")
        sys.exit(True)

try:
    if args[2] == "QUIET":
        quiet = True
except:
    quiet = False

if len(args) < 1:
    print("No EMULATOR or REMOTE specified")
    sys.exit(True)

# check if we are using a REMOTE system
remote = ""
remote_type = ""
# if string.find(args[0], "emulator:") == 0:
if args[0].startswith("emulator:"):
    remote = args[0][9:]
    em_remote = True
    remote_type = "EMULATOR"
else:
    em_remote = False

# if string.find(args[0], "reader:") == 0
if args[0].startswith("reader:"):
    remote = args[0][7:]
    rd_remote = True
    remote_type = "READER"
    emulator = card
else:
    rd_remote = False


if remote:
    host = remote[: remote.find(":")]
    port = int(remote[remote.find(":") + 1 :])
    connection = connect_to(host, port, remote_type)
else:
    try:
        readernum = int(args[0])
        emulator = rfidiot.RFIDIOt.rfidiot(readernum, card.readertype, "", "", "", "", "", "")
        print("  Emulator:", end="")
        emulator.info("")
        if emulator.readersubtype != card.READER_ACS:
            print("EMULATOR is not an ACS")
            sys.exit(True)
    except:
        print("Couldn't initialise EMULATOR on reader", args[0])
        sys.exit(True)

# always check at least one device locally
if card.readersubtype != card.READER_ACS:
    print("READER is not an ACS")
    if remote:
        connection.close()
    sys.exit(True)

if card.acs_send_apdu(PN532_APDU["GET_PN532_FIRMWARE"]):
    if remote:
        send_data(connection, card.data)
        print("  Local NXP PN532 Firmware:")
    else:
        print("  Reader NXP PN532 Firmware:")
    if card.data[:4] != PN532_OK:
        print("  Bad data from PN532:", card.data)
        if remote:
            connection.close()
        sys.exit(True)
    else:
        pn532_print_firmware(card.data)

if remote:
    data = recv_data(connection)
    print("  Remote NXP PN532 Firmware:")
else:
    if emulator.acs_send_apdu(PN532_APDU["GET_PN532_FIRMWARE"]):
        data = card.data
    emulator.acs_send_apdu(card.PCSC_APDU["ACS_LED_ORANGE"])
    print("  Emulator NXP PN532 Firmware:")

if data[:4] != PN532_OK:
    print("  Bad data from PN532:", data)
    if remote:
        connection.close()
    sys.exit(True)
else:
    pn532_print_firmware(data)

if not remote or remote_type == "EMULATOR":
    card.waitfortag("  Waiting for source TAG...")
    full_uid = card.uid
    sens_res = [card.sens_res]
    sel_res = [card.sel_res]
if remote:
    if remote_type == "READER":
        print("  Waiting for remote TAG...")
        connection.settimeout(None)
        full_uid = recv_data(connection)
        sens_res = [recv_data(connection)]
        sel_res = [recv_data(connection)]
    else:
        send_data(connection, card.uid)
        send_data(connection, card.sens_res)
        send_data(connection, card.sel_res)

mode = ["00"]
print("         UID:", full_uid)
uid = [full_uid[2:]]
print("    sens_res:", sens_res[0])
print("     sel_res:", sel_res[0])
print()
felica = ["01fea2a3a4a5a6a7c0c1c2c3c4c5c6c7ffff"]
nfcid = ["aa998877665544332211"]
try:
    lengt = ["%02x" % (len(args[6]) / 2)]
    gt = [args[6]]
except:
    lengt = ["00"]
    gt = [""]
try:
    lentk = ["%02x" % (len(args[7]) / 2)]
    tk = [args[7]]
except:
    lentk = ["00"]
    tk = [""]

if not remote or remote_type == "EMULATOR":
    if card.acs_send_apdu(PN532_APDU["GET_GENERAL_STATUS"]):
        data = card.data
if remote:
    if remote_type == "EMULATOR":
        send_data(connection, data)
    else:
        data = recv_data(connection)

tags = pn532_print_status(data)
if tags > 1:
    print("  Too many TAGS to EMULATE!")
    if remote:
        connection.close()
    sys.exit(True)

# emulator.acs_send_apdu(emulator.PCSC_APDU['ACS_SET_PARAMETERS']+['14'])

if not remote or remote_type == "READER":
    print("  Waiting for EMULATOR activation...")
    status = emulator.acs_send_apdu(
        PN532_APDU["TG_INIT_AS_TARGET"] + mode + sens_res + uid + sel_res + felica + nfcid + lengt + gt + lentk + tk
    )
    if not status or emulator.data[:4] != "D58D":
        print(
            "Target Init failed:",
            emulator.errorcode,
            emulator.get_error_str(card.errorcode),
        )
        if remote:
            connection.close()
        sys.exit(True)
    data = emulator.data
if remote:
    if remote_type == "READER":
        send_data(connection, data)
    else:
        print("  Waiting for remote EMULATOR activation...")
        connection.settimeout(None)
        data = recv_data(connection)

mode = int(data[4:6], 16)
baudrate = mode & 0x70
print("  Emulator activated:")
print("         UID: 08%s" % uid[0])
print("    Baudrate:", PN532_BAUDRATES[baudrate])
print("        Mode:", end="")
if mode & 0x08:
    print("ISO/IEC 14443-4 PICC")
if mode & 0x04:
    print("DEP")
framing = mode & 0x03
print("     Framing:", PN532_FRAMING[framing])
initiator = data[6:]
print("   Initiator:", initiator)
print()

print("  Waiting for APDU...")
started = False
try:
    while 42:
        # wait for emulator to receive a command
        if not remote or remote_type == "READER":
            status = emulator.acs_send_apdu(PN532_APDU["TG_GET_DATA"])
            data = emulator.data
            # if not status or not emulator.data[:4] == 'D587':
            if not status:
                print(
                    "Target Get Data failed:",
                    emulator.errorcode,
                    emulator.get_error_str(card.errorcode),
                )
                print("Data:", emulator.data)
                if remote:
                    connection.close()
                sys.exit(True)
        if remote:
            if remote_type == "READER":
                send_data(connection, data)
            else:
                connection.settimeout(None)
                data = recv_data(connection)
        errorcode = int(data[4:6], 16)
        if errorcode != 0x00:
            if remote:
                connection.close()
            if errorcode == 0x29:
                if logfile:
                    logfile.close()
                    logfile = None
                print("  Session ended: EMULATOR released by Initiator")
                if not remote or remote_type == "READER":
                    emulator.acs_send_apdu(card.PCSC_APDU["ACS_LED_GREEN"])
                sys.exit(False)
            print("Error:", PN532_ERRORS[errorcode])
            sys.exit(True)
        if not quiet:
            print("<<", data[6:])
        else:
            if not started:
                print("  Logging started...")
                started = True
        if logfile:
            logfile.write("<< %s\n" % data[6:])
            logfile.flush()
        # relay command to tag
        if not remote or remote_type == "EMULATOR":
            status = card.acs_send_direct_apdu(data[6:])
            data = card.data
            errorcode = card.errorcode
        if remote:
            if remote_type == "EMULATOR":
                send_data(connection, data)
                send_data(connection, errorcode)
            else:
                data = recv_data(connection)
                errorcode = recv_data(connection)
        if not quiet:
            print(">>", data, errorcode)
        if logfile:
            logfile.write(">> %s %s\n" % (data, errorcode))
            logfile.flush
        # relay tag's response back via emulator
        if not remote or remote_type == "READER":
            status = emulator.acs_send_apdu(PN532_APDU["TG_SET_DATA"] + [data] + [errorcode])
except:
    if logfile:
        logfile.close()
        logfile = None
    print("  Session ended with possible errors")
    if remote:
        connection.close()
    if not remote or remote_type == "READER":
        emulator.acs_send_apdu(card.PCSC_APDU["ACS_LED_GREEN"])
    sys.exit(True)
