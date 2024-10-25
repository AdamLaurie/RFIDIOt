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
except:
    print("Couldn't open reader!")
    sys.exit(True)

print()
card.info("rfidiot-cli v0.1")

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
    if command == "DUMP":
        start = int(args.pop(), 16)
        end = int(args.pop(), 16)
        print()
        print(f"  Dumping data blocks {start:02X} to {end:02X}:")
        print()
        sector = start
        while sector <= end:
            if card.readblock(sector):
                print("    %02X: %s %s" % (sector, card.data, card.ReadablePrint(card.data.decode("hex"))))
            else:
                print("    Failed: " + card.get_error_str(card.errorcode))
            sector += 1
        continue
    if command == "FILE":
        mode = args.pop().upper()
        if mode == "A":
            isofile = args.pop().encode("hex")
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
        if card.hsselect(speed):
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
        if card.select():
            print("    Tag ID:", card.uid, "   Tag Type:", end="")
            if card.readertype == card.READER_ACG and card.readername.find("LFX") == 0:
                print(card.LFXTags[card.tagtype])
            else:
                print(card.tagtype)
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
            data = ""
            sector = start
            print("    Reading...")
            while sector <= end:
                if card.login(sector, Mifare_KeyType, Mifare_Key) and card.readMIFAREblock(sector):
                    data += card.MIFAREdata.decode("hex")
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
                block = data[p : p + 16].encode("hex")
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
                            card.ReadablePrint(card.MIFAREdata.decode("hex")),
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
                        outfile.write(card.MIFAREdata.decode("hex"))
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
            end = start + len(data) / 16 - 1
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
                block = data[p : p + 16].encode("hex")
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
        if card.select():
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
