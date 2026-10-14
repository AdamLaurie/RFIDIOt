#!/usr/bin/python3
#  rfidiot-cli.py - CLI for rfidiot
#
#  Adam Laurie <adam@algroup.co.uk>
#  http://rfidiot.org/
#
#  This code is copyright (c) Adam Laurie, 2012, All rights reserved.
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


#
# This program is intended to illustrate RFIDIOt's capabilities. It is deliberately
# written in a style that is easy to understand rather then one that is elegant
# or efficient. Everything is done in longhand so that individual functions can
# be easily understood and extracted.
#
# On the other hand, due to it's completely open structure, it can be a powerful
# tool when commands are combined, and it's easy to create shell scripts that
# perform one-off tasks that are not worth writing an entire program for.


import sys
import time
import rfidiot

args = rfidiot.args
chelp = rfidiot.help

if chelp or len(sys.argv) == 1:
    print()
    print("Usage: %s [OPTIONS] <COMMAND> [ARG(s)] ... [<COMMAND> [ARG(s)] ... ]" % sys.argv[0])
    print()
    print("  Commands:")
    print()
    print('     AID <AID|"ALL"|"ANY">                            Select ISO 7816 AID')
    print("     AIDS                                             List well known AIDs")
    print('     APDU <CLA> <INS> <P1> <P2> <LC> <DATA> <LE>      Send raw ISO 7816 APDU (use "" for empty elements)')
    print("     CHANGE <MESSAGE>                                 Print message and wait for TAG to change")
    print("     CHAMELEON <COMMAND> [<ARGS> ... ]                Chameleon Ultra emulator (needs -R READER_CHAMELEON):")
    print("        INFO                                            List the 8 slots and the active one")
    print("        SLOT <n> UID <HEX> [TYPE <name>]                Emulate an arbitrary UID on slot <n> (1-8)")
    print("        SLOT <n> MFLOAD <FILE>                          Load a MIFARE dump onto slot <n> and emulate it")
    print("        REBOOT                                          Reboot the device (DFU bootloader)")
    print("     DESFIRE <COMMAND> [<ARGS> ... ]                  NXP DESFire native commands (SELECT the tag first;")
    print("                                                      args are required - chain more DESFIRE commands after):")
    print("        VERSION                                         GetVersion (HW/SW/UID, decoded)")
    print("        AIDS                                            GetApplicationIDs")
    print("        DFNAMES                                         GetDFNames (ISO DF names)")
    print("        FREEMEM                                         GetFreeMemory")
    print("        SELECT <AID>                                    SelectApplication (AID MSB-first, 000000 = PICC master)")
    print("        AUTH <KEYNO> <AES-KEY>                          AuthenticateAES, key <KEYNO>; AES-KEY = 32 hex or 0 (all-zero)")
    print("        KEYSETTINGS                                     GetKeySettings (settings, key count, key type)")
    print("        KEYVERSION <KEYNO>                              GetKeyVersion")
    print("        FILEIDS                                         GetFileIDs")
    print("        FILESETTINGS <FILENO>                           GetFileSettings (type, comm, access rights, size)")
    print("        READ <FILENO> <OFFSET> <LENGTH>                 ReadData (hex; LENGTH 0 = whole file)")
    print("        GETVALUE <FILENO>                               GetValue (value file)")
    print("        RECORDS <FILENO> <OFFSET> <NUM>                 ReadRecords (hex; NUM 0 = all)")
    print("        CMD <INS> <DATA>                                raw native command (INS hex; DATA hex or 0 for none)")
    print("     DUMP <START> <END>                               Show data blocks")
    print('     FILE <"A|H"> <ASCII|HEX>                         Select ISO 7816 FILE')
    print("     HSS <SPEED>                                      High Speed Select TAG. SPEED values are:")
    print("                                                        1 == 106 kBaud")
    print("                                                        2 == 212 kBaud")
    print("                                                        4 == 424 kBaud")
    print("                                                        8 == 848 kBaud")
    print("     IDENTIFY                                         Show TAG type")
    print("     MF <COMMAND> [<ARGS> ... ]                       Mifare commands:")
    print('        AUTH <"A|B"> <BLOCK>                            Authenticate with KEY A or B (future authentications')
    print("                                                        are automated)")
    print("        CLONE <HEX KEY>                                 Duplicate a Mifare TAG (KEY is KEY A of BLANK)")
    print("        DUMP <START> <END>                              Show data blocks")
    print('        KEY <"A|B"> <HEX KEY>                           Set Mifare KEY A or B')
    print("        READ <START> <END> <FILE>                       Read data blocks and save as FILE")
    print("        WIPE                                            Set Mifare TAG to all 00")
    print("        WRITE <START> <FILE>                            Write data blocks from FILE (note that KEY A will")
    print("                                                        be inserted from previously set value and KEY B")
    print("                                                        will also be inserted if set, overriding FILE value)")
    print("     PROMPT <MESSAGE>                                 Print message and wait for Y/N answer (exit if N)")
    print("     SCRIPT <FILE>                                    Read commands from FILE (see script.txt for example)")
    print("     SELECT                                           Select TAG")
    print("     WAIT <MESSAGE>                                   Print message and wait for TAG")
    print("     WRITEHEX <BLOCK> <HEX>                           Write HEX data to BLOCK")
    print()
    print("  Commands will be executed sequentially and must be combined as appropriate.")
    print("  Block numbers must be specified in HEX.")
    print()
    print("  Examples:")
    print()
    print('     Select TAG, set Mifare KEY A to "FFFFFFFFFFFF" and authenticate against sector 0:')
    print()
    print("       rfidiot-cli.py select mf key a FFFFFFFFFFFF mf auth a 0")
    print()
    print("     Write Mifare data to new TAG, changing Key A to 112233445566 (writing block 0 is allowed to fail):")
    print()
    print("       rfidiot-cli.py select mf key a FFFFFFFFFFFF mf auth a 0 mf key a 112233445566 mf write 0 mifare.dat")
    print()
    print("     Clone a Mifare TAG to a new blank:")
    print()
    print("       rfidiot-cli.py select mf key a 112233445566 mf auth a 0 mf clone FFFFFFFFFFFF")
    sys.exit(True)

try:
    card = rfidiot.card
except Exception as e:
    print("Couldn't open reader! (%s)" % e)
    sys.exit(True)

print()
card.info("rfidiot-cli v3.1g")

# globals
Mifare_Key = None
Mifare_KeyType = None
Mifare_KeyA = None
Mifare_KeyB = None

# main loop
args.reverse()
while args:
    command = args.pop().upper()
    if command == "AID":
        arg = args.pop().upper()
        if arg in ["ANY", "ALL"]:
            aids = list(card.AIDS.keys())
        else:
            aids = [arg]
        while aids:
            aid = aids.pop()
            print()
            print("  Selecting AID: %s" % aid, end="")
            try:
                print("(%s)" % card.AIDS[aid], end="")
            except:
                pass
            print()
            print()
            if card.iso_7816_select_file(aid, card.ISO_7816_SELECT_BY_NAME, "0C"):
                print("    OK")
                if arg == "ANY":
                    break
            else:
                print("    Failed: " + card.get_error_str(card.errorcode))
        continue
    if command == "AIDS":
        print()
        print("  AIDs:")
        print()
        for aid in card.AIDS.items():
            print("    % 24s: %s" % (aid[0], aid[1]))
        print()
        continue
    if command == "APDU":
        cla = args.pop().upper()
        ins = args.pop().upper()
        p1 = args.pop().upper()
        p2 = args.pop().upper()
        lc = args.pop().upper()
        data = args.pop().upper()
        le = args.pop().upper()
        print()
        print("  Sending APDU:", cla + ins + p1 + p2 + lc + data + le)
        print()
        if card.send_apdu("", "", "", "", cla, ins, p1, p2, lc, data, le):
            print("    OK")
            print("    Data:", card.data)
        else:
            print("    Failed: " + card.get_error_str(card.errorcode))
        continue
    if command == "CHANGE":
        message = args.pop()
        print()
        current = card.uid
        card.waitfortag(message)
        while card.uid == current or card.uid == '':
            card.waitfortag("")
        print()
        continue
    if command == "DESFIRE":
        # NXP MIFARE DESFire native commands, sent over the ISO 7816 wrapping
        # (CLA 90, native INS, Le 00; chained commands continue with 90 AF). The
        # DESFire status comes back as SW2 after 0x91 (9100 = OK, 91AF = another
        # frame follows). Works over any reader that passes APDUs (libnfc, -f ccid,
        # -r ccid/PC-SC, TWN4, Chameleon). SELECT the tag first.
        DF_STATUS = {
            "9100": "OK", "91AF": "ADDITIONAL FRAME", "910C": "NO CHANGES",
            "910E": "OUT OF MEMORY", "911C": "ILLEGAL COMMAND", "911E": "INTEGRITY ERROR",
            "9140": "NO SUCH KEY", "917E": "LENGTH ERROR", "919D": "PERMISSION DENIED",
            "919E": "PARAMETER ERROR", "91A0": "APPLICATION NOT FOUND", "91A1": "APPL INTEGRITY ERROR",
            "91AE": "AUTHENTICATION ERROR", "91AF": "ADDITIONAL FRAME", "91BE": "BOUNDARY ERROR",
            "91C1": "CARD INTEGRITY ERROR", "91CA": "COMMAND ABORTED", "91CD": "CARD DISABLED",
            "91CE": "COUNT ERROR", "91DE": "DUPLICATE", "91EE": "EEPROM ERROR",
            "91F0": "FILE NOT FOUND", "91F1": "FILE INTEGRITY ERROR",
        }

        def df_apdu(ins, data=""):
            "send one DESFire native command; return (data_hex, sw_hex)"
            if data:
                card.send_apdu("", "", "", "", "90", ins, "00", "00", "%02X" % (len(data) // 2), data, "00")
            else:
                card.send_apdu("", "", "", "", "90", ins, "00", "00", "", "", "00")
            return card.data.upper(), card.errorcode.upper()

        def df_full(ins, data=""):
            "send a command and gather all chained (91AF) frames: (all_data, final_sw)"
            d, sw = df_apdu(ins, data)
            while sw == "91AF":
                more, sw = df_apdu("AF")
                d += more
            return d, sw

        def df_status(sw):
            return "%s (%s)" % (sw, DF_STATUS.get(sw, "unknown"))

        def df_rev_aid(aid):
            "AID is 3 bytes LSB-first on the wire; show/accept it MSB-first (F53630)"
            return aid[4:6] + aid[2:4] + aid[0:2]

        dfcommand = args.pop().upper()
        print()
        if dfcommand == "VERSION":
            d, sw = df_full("60")       # GetVersion: HW frame, SW frame, UID/production frame
            if sw != "9100" or len(d) < 42:
                print("  GetVersion: " + df_status(sw))
                continue
            hw, soft, prod = d[0:14], d[14:28], d[28:]
            print("  GetVersion:")
            print("    Hardware: vendor %s type %s subtype %s ver %s.%s storage 0x%s proto %s" %
                  (hw[0:2], hw[2:4], hw[4:6], hw[6:8], hw[8:10], hw[10:12], hw[12:14]))
            print("    Software: vendor %s type %s subtype %s ver %s.%s storage 0x%s proto %s" %
                  (soft[0:2], soft[2:4], soft[4:6], soft[6:8], soft[8:10], soft[10:12], soft[12:14]))
            print("    UID %s  batch %s  week/year %s%s" % (prod[0:14], prod[14:24], prod[24:26], prod[26:28]))
            gen = {"01": "EV1 / D40", "12": "EV2", "33": "EV3"}.get(hw[6:8], "?")
            print("    -> DESFire %s (HW major 0x%s)" % (gen, hw[6:8]))
            continue
        if dfcommand == "AIDS":
            d, sw = df_full("6A")       # GetApplicationIDs
            if sw != "9100":
                print("  GetApplicationIDs: " + df_status(sw))
                continue
            aids = [d[i:i + 6] for i in range(0, len(d), 6)]
            print("  Applications (%d):" % len(aids))
            for a in aids:
                print("    AID %s" % df_rev_aid(a))
            if not aids:
                print("    (none - PICC level only)")
            continue
        if dfcommand == "SELECT":
            aid = args.pop().upper()                    # MSB-first, e.g. F53630 (000000 = PICC master)
            d, sw = df_apdu("5A", df_rev_aid(aid))       # send LSB-first
            print("  SelectApplication %s: %s" % (aid, df_status(sw)))
            continue
        if dfcommand == "AUTH":
            # AES authenticate (90 AA); default key is all-zero (DESFire factory default)
            keyno = args.pop().upper()                   # key number, e.g. 00
            keyhex = args.pop().upper()                   # 32 hex (16-byte AES key), or 0 for all-zero
            if keyhex in ("0", "ZERO"):
                keyhex = "00" * 16
            try:
                from Crypto.Cipher import AES
                import os as _os
                key = bytes.fromhex(keyhex)
                assert len(key) == 16
            except (ValueError, AssertionError):
                print("  AUTH: key must be 32 hex chars (16-byte AES key)")
                continue
            d, sw = df_apdu("AA", keyno)                  # AuthenticateAES, key <keyno>
            if sw != "91AF" or len(d) != 32:
                print("  AuthenticateAES key %s: %s (no challenge - AES key?)" % (keyno, df_status(sw)))
                continue
            ek = bytes.fromhex(d)
            rndb = AES.new(key, AES.MODE_CBC, bytes(16)).decrypt(ek)
            rndb_rot = rndb[1:] + rndb[:1]
            rnda = _os.urandom(16)
            token = AES.new(key, AES.MODE_CBC, ek).encrypt(rnda + rndb_rot)
            d, sw = df_apdu("AF", token.hex().upper())
            which = "all-zero key" if keyhex == "00" * 16 else "key " + keyhex
            print("  AuthenticateAES key %s with %s: %s" % (keyno, which, df_status(sw)))
            if sw == "9100":
                print("    *** AUTH OK - the key is %s ***" % keyhex)
            else:
                print("    auth failed (as expected unless %s is the real key)" % which)
            continue

        def le3(x):
            "3-byte little-endian hex from a hex/int string (offsets, lengths, values)"
            n = int(x, 16)
            return "%02X%02X%02X" % (n & 0xFF, (n >> 8) & 0xFF, (n >> 16) & 0xFF)

        def ar_name(n):
            return {0xE: "free", 0xF: "never"}.get(n, "key %X" % n)

        if dfcommand == "FREEMEM":                 # GetFreeMemory (0x6E)
            d, sw = df_apdu("6E")
            if sw == "9100" and len(d) >= 6:
                print("  Free memory: %d bytes" % int(d[4:6] + d[2:4] + d[0:2], 16))
            else:
                print("  GetFreeMemory: " + df_status(sw))
            continue
        if dfcommand == "KEYSETTINGS":             # GetKeySettings (0x45)
            d, sw = df_apdu("45")
            if sw == "9100" and len(d) >= 4:
                settings = int(d[0:2], 16); maxk = int(d[2:4], 16)
                ktype = {0x00: "DES/3DES", 0x40: "3K3DES", 0x80: "AES"}.get(maxk & 0xC0, "?")
                print("  KeySettings: 0x%02X, %d keys, type %s" % (settings, maxk & 0x0F, ktype))
                print("    change-key access: %s; config %s; create/delete w/o master-auth %s; dir-list w/o master-auth %s; master changeable %s" % (
                    ar_name((settings >> 4) & 0x0F),
                    "frozen" if not settings & 0x08 else "allowed",
                    "yes" if settings & 0x04 else "no",
                    "yes" if settings & 0x02 else "no",
                    "yes" if settings & 0x01 else "no"))
            else:
                print("  GetKeySettings: " + df_status(sw))
            continue
        if dfcommand == "KEYVERSION":              # GetKeyVersion (0x64) <keyno>
            keyno = args.pop().upper()
            d, sw = df_apdu("64", keyno)
            print("  Key %s version: %s (%s)" % (keyno, d if sw == "9100" else "-", df_status(sw)))
            continue
        if dfcommand == "FILEIDS":                 # GetFileIDs (0x6F)
            d, sw = df_full("6F")
            if sw != "9100":
                print("  GetFileIDs: " + df_status(sw)); continue
            fids = [d[i:i + 2] for i in range(0, len(d), 2)]
            print("  Files (%d): %s" % (len(fids), " ".join(fids) or "(none)"))
            continue
        if dfcommand == "FILESETTINGS":            # GetFileSettings (0xF5) <fileno>
            fileno = args.pop().upper()
            d, sw = df_apdu("F5", fileno)
            if sw != "9100" or len(d) < 8:
                print("  GetFileSettings file %s: %s" % (fileno, df_status(sw))); continue
            ftype = {"00": "Standard data", "01": "Backup data", "02": "Value",
                     "03": "Linear record", "04": "Cyclic record"}.get(d[0:2], "type " + d[0:2])
            comm = {"00": "plain", "01": "MACed", "03": "enciphered"}.get(d[2:4], d[2:4])
            ar = int(d[6:8] + d[4:6], 16)          # 2 bytes LSB
            print("  File %s: %s, comm %s" % (fileno, ftype, comm))
            print("    access: read=%s write=%s read&write=%s changeAR=%s" % (
                ar_name((ar >> 12) & 0xF), ar_name((ar >> 8) & 0xF),
                ar_name((ar >> 4) & 0xF), ar_name(ar & 0xF)))
            rest = d[8:]
            if d[0:2] in ("00", "01") and len(rest) >= 6:
                print("    size: %d bytes" % int(rest[4:6] + rest[2:4] + rest[0:2], 16))
            continue
        if dfcommand == "GETVALUE":                # GetValue (0x6C) <fileno>
            fileno = args.pop().upper()
            d, sw = df_full("6C", fileno)
            if sw == "9100" and len(d) >= 8:
                print("  Value file %s = %d" % (fileno, int(d[6:8] + d[4:6] + d[2:4] + d[0:2], 16)))
            else:
                print("  GetValue file %s: %s" % (fileno, df_status(sw)))
            continue
        if dfcommand == "READ":                    # ReadData (0xBD) <fileno> [<offset> <length>]
            fileno = args.pop().upper()
            off = args.pop()
            length = args.pop()        # 0 = whole file
            d, sw = df_full("BD", fileno + le3(off) + le3(length))
            print("  ReadData file %s off %s len %s: %s" % (fileno, off, length, df_status(sw)))
            if d:
                print("    %s" % d)
            continue
        if dfcommand == "RECORDS":                 # ReadRecords (0xBB) <fileno> [<offset> <num>]
            fileno = args.pop().upper()
            off = args.pop()
            num = args.pop()           # 0 = all records
            d, sw = df_full("BB", fileno + le3(off) + le3(num))
            print("  ReadRecords file %s off %s num %s: %s" % (fileno, off, num, df_status(sw)))
            if d:
                print("    %s" % d)
            continue
        if dfcommand == "DFNAMES":                 # GetDFNames (0x6D): one DF per frame
            entries = []
            d, sw = df_apdu("6D")
            while True:
                if d:
                    entries.append(d)              # AID(3 LSB) + ISO FID(2) + DF name
                if sw != "91AF":
                    break
                d, sw = df_apdu("AF")
            print("  GetDFNames: " + df_status(sw))
            for e in entries:
                aid = df_rev_aid(e[0:6]) if len(e) >= 6 else "?"
                fid = e[6:10] if len(e) >= 10 else ""
                name = e[10:] if len(e) > 10 else ""
                print("    AID %s  ISO-FID %s  DFname %s" % (aid, fid, name))
            if not entries:
                print("    (none)")
            continue
        if dfcommand == "CMD":                     # raw native command: CMD <ins> [<data-hex>]
            ins = args.pop().upper()
            data = args.pop().upper()                 # hex, or 0/- for none
            if data in ("0", "-", "NONE"):
                data = ""
            d, sw = df_full(ins, data)
            print("  CMD 90%s %s -> %s %s" % (ins, data, d, df_status(sw)))
            continue
        print("  Unknown DESFIRE command:", dfcommand)
        print("  commands: VERSION AIDS SELECT AUTH FREEMEM KEYSETTINGS KEYVERSION")
        print("            FILEIDS FILESETTINGS GETVALUE READ RECORDS DFNAMES CMD")
        continue
    if command == "DUMP":
        start = int(args.pop(), 16)
        end = int(args.pop(), 16)
        print()
        print(f"  Dumping data blocks {start:02X} to {end:02X}:")
        print()
        sector = start
        while sector <= end:
            if card.readblock(sector):
                print("    %02X: %s %s" % (sector, card.data, card.ReadablePrint(card.ToBinary(card.data))))
            else:
                print("    Failed: " + card.get_error_str(card.errorcode))
            sector += 1
        continue
    if command == "FILE":
        mode = args.pop().upper()
        if mode == "A":
            isofile = card.ToHex(args.pop())
        elif mode == "H":
            isofile = args.pop().upper()
        else:
            print("Invalid FILE mode:", args.pop().upper())
            sys.exit(True)
        print()
        print("  Selecting ISO File:", isofile)
        print()
        if card.iso_7816_select_file(isofile, card.ISO_7816_SELECT_BY_NAME, "00"):
            print("    OK")
        else:
            print("    Failed: " + card.get_error_str(card.errorcode))
        continue
    if command == "HSS":
        speed = "%02X" % int(args.pop())
        print()
        print(f"  High Speed Selecting ({card.ISO_SPEED[speed]})")
        print()
        # try ISO 14443-B if no Type A card (only libnfc/CCID distinguish them)
        if card.hsselect(speed) or card.hsselect(speed, "B"):
            print("    Tag ID: " + card.uid)
        else:
            if card.errorcode:
                print("    " + card.get_error_str(card.errorcode))
            else:
                print("    No card present")
        continue
    if command == "IDENTIFY":
        print()
        print("  Identiying TAG")
        print()
        # try ISO 14443-B if no Type A card (only libnfc/CCID distinguish them)
        if card.select() or card.select("B"):
            print("    Tag ID:", card.uid, "   Tag Type:", end="")
            if card.readertype == card.READER_ACG and card.readername.find("LFX") == 0:
                print(card.LFXTags[card.tagtype])
            else:
                print(card.tagtype)
            if card.readertype in (card.READER_LIBNFC, card.READER_TWN4) and card.sel_res:
                print("      ATQA:", card.sens_res, "  SAK:", card.sel_res)
                print("      Type: ISO 14443A -", card.iso14443a_type())
                if card.atr:
                    print("      ATS:", card.atr)
            if card.readertype in (card.READER_LIBNFC, card.READER_TWN4) and card.tagtype == "ISO 14443B":
                print("      PUPI:", card.pupi, "  Application Data:", card.appdata, "  Protocol Info:", card.protocol)
            if card.readertype == card.READER_PCSC:
                if card.tagtype.find("ISO 15693") >= 0:
                    print()
                    print("         Manufacturer:", end="")
                    try:
                        print(card.ISO7816Manufacturer[card.uid[2:4]])
                    except:
                        print("Unknown (%s)" % card.uid[2:4])
                if not card.readersubtype == card.READER_ACS:
                    print()
                    card.PCSCPrintATR(card.pcsc_atr)
        else:
            print("    No card present", end="")
        continue
    if command == "MF":
        print()
        mfcommand = args.pop().upper()
        if mfcommand == "AUTH":
            keytype = args.pop().upper()
            sector = int(args.pop(), 16)
            print(f"  Authenticating to sector {sector:02X} with Mifare Key", end="")
            Mifare_KeyType = keytype
            if keytype == "A":
                Mifare_Key = Mifare_KeyA
                print(f"A ({Mifare_Key})")
            elif keytype == "B":
                Mifare_Key = Mifare_KeyB
                print(f"B ({Mifare_Key})")
            else:
                print("failed! Invalid keytype:", keytype)
                sys.exit(True)
            print()
            if card.login(sector, Mifare_KeyType, Mifare_Key):
                print("    OK")
            else:
                print("    Failed: " + card.get_error_str(card.errorcode))
            continue
        if mfcommand == "CLONE":
            print("  Cloning Mifare TAG", end="")
            if not Mifare_KeyA:
                print("failed! KEY A not set!")
                sys.exit(True)
            if not Mifare_KeyType or not Mifare_Key:
                print("failed! No authentication performed!")
                sys.exit(True)
            print()
            print()
            print("    Key A will be set to:", Mifare_KeyA)
            print()
            blank_key = args.pop()
            start = 0
            end = 0x3F
            data = bytearray()
            sector = start
            print("    Reading...")
            while sector <= end:
                if card.login(sector, Mifare_KeyType, Mifare_Key) and card.readMIFAREblock(sector):
                    data += card.ToBinary(card.MIFAREdata)
                else:
                    print("    Failed: " + card.get_error_str(card.errorcode))
                sector += 1
            print()
            print("      OK")
            print()
            # wait for tag to change (same UID is OK)
            card.waitfortag("    Replace TAG with TARGET")
            while card.select():
                pass
            time.sleep(0.5)
            while not card.select():
                pass
            time.sleep(0.5)
            print()
            print()
            print("    Writing...")
            sector = start
            p = 0
            while sector <= end:
                block = card.ToHex(data[p : p + 16])
                if not (sector + 1) % 4:
                    # trailing block must contain keys, so reconstruct
                    block = Mifare_KeyA + block[12:]
                if not (card.login(sector, "A", blank_key) and card.writeblock(sector, block)):
                    if sector == 0:
                        print("      Sector 0 write failed")
                        card.select()
                    else:
                        print("      Failed: " + card.get_error_str(card.errorcode))
                        sys.exit(True)
                sector += 1
                p += 16
            print()
            print("      OK")
            continue
        if mfcommand == "DUMP":
            start = int(args.pop(), 16)
            end = int(args.pop(), 16)
            print(f"  Dumping data blocks {start:02X} to {end:02X}", end="")
            if not Mifare_KeyType or not Mifare_Key:
                print("failed! No authentication performed!")
                sys.exit(True)
            print()
            print()
            sector = start
            while sector <= end:
                if card.login(sector, Mifare_KeyType, Mifare_Key) and card.readMIFAREblock(sector):
                    print(
                        "    %02X: %s %s"
                        % (
                            sector,
                            card.MIFAREdata,
                            card.ReadablePrint(card.ToBinary(card.MIFAREdata)),
                        )
                    )
                else:
                    print("    Failed: " + card.get_error_str(card.errorcode))
                sector += 1
            continue
        if mfcommand == "KEY":
            print("  Setting Mifare Key", end="")
            keytype = args.pop().upper()
            if keytype == "A":
                Mifare_KeyA = args.pop().upper()
                print("A:", Mifare_KeyA)
            elif keytype == "B":
                Mifare_KeyB = args.pop().upper()
                print("B:", Mifare_KeyB)
            else:
                print("failed! Invalid keytype:", keytype)
                sys.exit(True)
            continue

        if mfcommand == "READ":
            start = int(args.pop(), 16)
            end = int(args.pop(), 16)
            filename = args.pop()
            print(f"  Reading data blocks {start:02X} to {end:02X} and saving as {filename}:", end="")
            if not Mifare_KeyType or not Mifare_Key:
                print("failed! No authentication performed!")
                sys.exit(True)
            with open(filename, "wb") as outfile:
                print()
                print()
                sector = start
                while sector <= end:
                    if card.login(sector, Mifare_KeyType, Mifare_Key) and card.readMIFAREblock(sector):
                        # readMIFAREblock() has already patched a sector trailer with
                        # the key that authenticated, so the dump can be cloned
                        outfile.write(card.ToBinary(card.MIFAREdata))
                    else:
                        print("    Failed: " + card.get_error_str(card.errorcode))
                    sector += 1

            #if not outfile:
            #    print("failed! Couldn't open output file!")
            #    sys.exit(True)
            print("    OK")
            continue

        if mfcommand == "WIPE":
            print("  Wiping Mifare TAG", end="")
            if not Mifare_KeyA:
                print("failed! KEY A not set!")
                sys.exit(True)
            if not Mifare_KeyB:
                print("failed! KEY B not set!")
                sys.exit(True)
            if not Mifare_KeyType or not Mifare_Key:
                print("failed! No authentication performed!")
                sys.exit(True)
            print()
            print()
            print("    Key A will be set to:", Mifare_KeyA)
            print("    Key B will be set to:", Mifare_KeyB)
            print()
            start = 1
            end = 0x3F
            sector = start
            perms = "FF078069"
            while sector <= end:
                if not (sector + 1) % 4:
                    # trailing block must contain keys, so reconstruct
                    block = Mifare_KeyA + perms + Mifare_KeyB
                else:
                    block = "00" * 16
                if not (card.login(sector, Mifare_KeyType, Mifare_Key) and card.writeblock(sector, block)):
                    print("    Failed: " + card.get_error_str(card.errorcode))
                    sys.exit(True)
                sector += 1
            print("    OK")
            continue

        if mfcommand == "WRITE":
            start = int(args.pop(), 16)
            filename = args.pop()
            with open(filename, "rb") as infile:
                data = infile.read()
            print("  Writing data from file", filename, end="")
            if len(data) % 16:
                print("failed! File length is not divisible by Mifare block length (16)!")
                sys.exit(True)
            if not Mifare_KeyA:
                print("failed! KEY A not set!")
                sys.exit(True)
            if not Mifare_KeyType or not Mifare_Key:
                print("failed! No authentication performed!")
                sys.exit(True)
            end = start + len(data) // 16 - 1
            print(f"to blocks {start:02X} to {end:02X}")
            print()
            print("    Key A will be set to:", Mifare_KeyA)
            if Mifare_KeyB:
                print("    Key B will be set to:", Mifare_KeyB)
            else:
                print("    Key B will be set as per file")
            print()
            sector = start
            p = 0
            while sector <= end:
                block = card.ToHex(data[p : p + 16])
                if not (sector + 1) % 4:
                    # trailing block must contain keys, so reconstruct
                    if Mifare_KeyB:
                        block = Mifare_KeyA + block[12:20] + Mifare_KeyB
                    else:
                        block = Mifare_KeyA + block[12:]
                if not (card.login(sector, Mifare_KeyType, Mifare_Key) and card.writeblock(sector, block)):
                    if sector == 0:
                        print("    Sector 0 write failed")
                        card.select()
                    else:
                        print("    Failed: " + card.get_error_str(card.errorcode))
                        sys.exit(True)
                sector += 1
                p += 16
            print("    OK")
            continue
        print("  Invalid MF command:", mfcommand)
        sys.exit(True)
    if command == "CHAMELEON":
        if card.readertype != card.READER_CHAMELEON:
            print("  CHAMELEON commands require a Chameleon Ultra (-R READER_CHAMELEON)")
            sys.exit(True)
        from rfidiot import pychameleon as pc
        cham = card.chameleon
        cucommand = args.pop().upper()
        if cucommand == "INFO":
            print()
            active = cham.get_active_slot()
            names = {v: k for k, v in pc.TAG_TYPES.items()}
            print("  Active slot: %d" % (active + 1))
            print("    Slot  HF                 LF")
            for i, (hf, lf) in enumerate(cham.get_slot_info()):
                hn = "-" if hf == 0 else names.get(hf, "0x%04X" % hf)
                ln = "-" if lf == 0 else names.get(lf, "0x%04X" % lf)
                print("     %d    %-17s  %-10s%s" % (i + 1, hn, ln, "  <= active" if i == active else ""))
            continue
        if cucommand == "REBOOT":
            print("  Rebooting the Chameleon via the DFU bootloader (the port will drop)...")
            cham.reboot()
            continue
        if cucommand == "SLOT":
            slot = int(args.pop())
            if not 1 <= slot <= pc.NUM_SLOTS:
                print("  Slot must be 1-%d" % pc.NUM_SLOTS)
                sys.exit(True)
            slot_fw = slot - 1
            sub = args.pop().upper()
            if sub == "UID":
                uid = card.ToBinary(args.pop())
                # optional trailing 'TYPE <name>' (only consume when present, as the
                # arg stream may continue with another command)
                type_name = "MIFARE_1K"
                if args and args[-1].upper() == "TYPE":
                    args.pop()
                    type_name = args.pop().upper()
                if type_name not in pc.TAG_TYPES:
                    print("  Unknown TYPE '%s'. One of: %s" % (type_name, ", ".join(sorted(pc.TAG_TYPES))))
                    sys.exit(True)
                atqa = cham.default_atqa(len(uid))
                sak = cham.default_sak(type_name)
                print("  Emulating UID %s on slot %d (%s, ATQA %s SAK %s)"
                      % (uid.hex().upper(), slot, type_name, atqa.hex().upper(), sak.hex().upper()))
                cham.emulate_14a(slot_fw, uid, atqa, sak, pc.TAG_TYPES[type_name])
                print("    OK")
                continue
            if sub == "MFLOAD":
                filename = args.pop()
                with open(filename, "rb") as f:
                    dump = f.read()
                if not dump or len(dump) % 16:
                    print("  Dump length %d is not a multiple of 16" % len(dump))
                    sys.exit(True)
                type_name = cham.type_from_blockcount(len(dump) // 16)
                block0 = dump[0:16]
                uid, sak, atqa = block0[0:4], block0[5:6], block0[6:8]
                print("  Loading %d blocks from %s onto slot %d (%s, UID %s)"
                      % (len(dump) // 16, filename, slot, type_name, uid.hex().upper()))
                cham.emulate_mfload(slot_fw, dump, pc.TAG_TYPES[type_name], uid, atqa, sak)
                print("    OK")
                continue
            print("  CHAMELEON SLOT needs UID or MFLOAD")
            sys.exit(True)
        print("  Invalid CHAMELEON command:", cucommand)
        sys.exit(True)
    if command == "PROMPT":
        message = args.pop()
        print()
        x = input(message).upper()
        if x == "N":
            sys.exit(False)
        continue

    if command == "SCRIPT":
        filename = args.pop()
        with open(filename, "rb") as infile:
            print()
            print("  Reading commands from", filename)
            # if not infile:
            #     print("failed! Can't open file!")
            #     sys.exit(True)
            script = []
            while 42:
                line = infile.readline()
                if line == "":
                    break
                line = line.strip()
                if line == "":
                    continue
                quoted = False
                for arg in line.split(" "):
                    # skip comments
                    if arg[0] == "#":
                        break
                    # quoted sections
                    if arg[0] in ['"', "'"]:
                        quoted = True
                        quote = ""
                        arg = arg[1:]
                    if quoted:
                        if arg[-1] in ['"', "'"]:
                            quote += " " + arg[:-1]
                            quoted = False
                            script.append(quote)
                        else:
                            quote += " " + arg
                    else:
                        script.append(arg)

        script.reverse()
        args += script
        continue

    if command == "SELECT":
        print()
        print("  Selecting TAG")
        print()
        # try ISO 14443-B if no Type A card (only libnfc/CCID distinguish them)
        if card.select() or card.select("B"):
            print("    Tag ID: " + card.uid)
            if card.readertype == card.READER_PCSC:
                print("    ATR: " + card.pcsc_atr)
        else:
            if card.errorcode:
                print("    Failed:  " + card.get_error_str(card.errorcode))
            else:
                print("    No card present")
        continue

    if command == "WAIT":
        message = args.pop()
        print()
        current = card.uid
        card.waitfortag(message)
        print()
        continue

    if command == "WRITEHEX":
        block = int(args.pop(), 16)
        data = args.pop().upper()
        print()
        print(f"  Writing data {data} to block {block:02x}", end="")
        if not card.writeblock(block, data):
            print("    Failed: " + card.get_error_str(card.errorcode))
            sys.exit(True)
        print("    OK")
        continue

    print()
    print("Unrecognised command:", command)
    sys.exit(True)
print()
sys.exit(False)
