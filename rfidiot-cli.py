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


def _xor(a, b):
    "byte-wise XOR of two equal-length byte strings"
    return bytes(x ^ y for x, y in zip(a, b))


def ReadablePrintHex(hexstr):
    "printable-ASCII rendering of a hex string (non-printable as '.')"
    try:
        return '"%s"' % "".join(
            chr(b) if 0x20 <= b < 0x7F else "." for b in bytes.fromhex(hexstr))
    except ValueError:
        return ""


# ---------------------------------------------------------------------------
# DESFire crypto / secure messaging.
#
# The DESFire authentication (legacy 0x0A, ISO 0x1A, AES 0xAA), session-key
# derivation, the D40 "inverted" CBC, the legacy CRC16/MAC/enciphered comms and
# the EV1 "new" secure messaging (CMAC chaining, CRC32, enciphered mode) below
# are RE-IMPLEMENTED in Python from the algorithms in **libfreefare**
# (https://github.com/nfc-tools/libfreefare, mifare_desfire.c /
# mifare_desfire_crypto.c / mifare_desfire_key.c, LGPL-3.0) - used as the
# authoritative reference and cross-checked against it. Credit and thanks to the
# libfreefare authors (Romuald Conty, Romain Tartiere, et al.).
# ---------------------------------------------------------------------------


def rotate_left(b, n=1):
    "rotate a byte string left by n bytes (DESFire token rotation)"
    return b[n:] + b[:n]


def aes_cmac(key, msg):
    "AES-CMAC (RFC 4493 / NIST SP 800-38B); returns the full 16-byte tag"
    from Crypto.Cipher import AES
    bs = 16
    ecb = AES.new(key, AES.MODE_ECB)

    def dbl(b):                       # GF(2^128) doubling (left shift, reduce by 0x87)
        n = (int.from_bytes(b, "big") << 1) & ((1 << (bs * 8)) - 1)
        if b[0] & 0x80:
            n ^= 0x87
        return n.to_bytes(bs, "big")

    k1 = dbl(ecb.encrypt(bytes(bs)))
    k2 = dbl(k1)
    if len(msg) and len(msg) % bs == 0:            # complete final block
        last = _xor(msg[-bs:], k1)
        head = msg[:-bs]
    else:                                          # pad 0x80 00.. and use K2
        padded = msg + b"\x80" + bytes(bs - 1 - (len(msg) % bs))
        last = _xor(padded[-bs:], k2)
        head = padded[:-bs]
    x = bytes(bs)
    for i in range(0, len(head), bs):
        x = ecb.encrypt(_xor(x, head[i:i + bs]))
    return ecb.encrypt(_xor(x, last))


def desfire_aes_session_key(rnda, rndb):
    "DESFire AES session key from the two 16-byte nonces (halves of each)"
    return rnda[0:4] + rndb[0:4] + rnda[12:16] + rndb[12:16]


def _des_e(k8, b):
    from Crypto.Cipher import DES
    return DES.new(k8, DES.MODE_ECB).encrypt(b)


def _des_d(k8, b):
    from Crypto.Cipher import DES
    return DES.new(k8, DES.MODE_ECB).decrypt(b)


def tdes_block(key, b, decrypt=False):
    "one 8-byte block through DES(8)/2K3DES(16)/3K3DES(24), built from single-DES "
    "primitives so weak/all-zero keys (which pycryptodome's DES3 rejects) work. "
    "EDE per NIST SP800-67: encrypt = E_K1 then D_K2 then E_K3."
    if len(key) == 8:
        k1 = k2 = k3 = key
    elif len(key) == 16:
        k1, k2, k3 = key[0:8], key[8:16], key[0:8]
    else:
        k1, k2, k3 = key[0:8], key[8:16], key[16:24]
    if decrypt:
        return _des_d(k1, _des_e(k2, _des_d(k3, b)))
    return _des_e(k3, _des_d(k2, _des_e(k1, b)))


def tdes_cbc(key, data, iv, decrypt, legacy):
    "(3)DES CBC over 8-byte blocks. legacy=True is the DESFire D40 'inverted' mode "
    "(encipher = block-decrypt, decipher = block-encrypt); legacy=False is standard "
    "CBC (ISO / AuthenticateISO). Returns (output, last_cipher_block)."
    # per libfreefare: RECEIVE always uses the block-DECRYPT op (MCO_DECYPHER);
    # SEND uses block-DECRYPT for legacy (D40) and block-ENCRYPT for standard (ISO/AES)
    out, prev = b"", iv
    for i in range(0, len(data), 8):
        blk = data[i:i + 8]
        if decrypt:                                  # recover plaintext from ciphertext
            out += _xor(tdes_block(key, blk, decrypt=True), prev)
            prev = blk
        else:                                        # encipher plaintext to ciphertext
            c = tdes_block(key, _xor(blk, prev), decrypt=legacy)
            out += c
            prev = c
    return out, prev


def crc32_jam(data):
    "DESFire CRC32 (reflected poly 0xEDB88320, init 0xFFFFFFFF, no final xor)"
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xEDB88320 if crc & 1 else crc >> 1
    return crc & 0xFFFFFFFF


def _df_block_encrypt(key, b, sm):
    if sm == "aes":
        from Crypto.Cipher import AES
        return AES.new(key, AES.MODE_ECB).encrypt(b)
    return tdes_block(key, b, decrypt=False)


def _df_block_decrypt(key, b, sm):
    if sm == "aes":
        from Crypto.Cipher import AES
        return AES.new(key, AES.MODE_ECB).decrypt(b)
    return tdes_block(key, b, decrypt=True)


def df_cmac_subkeys(key, sm):
    "CMAC subkeys K1/K2 from the session key (AES: 16-byte block, Rb 0x87; (3)DES: 8, 0x1B)"
    bs = 16 if sm == "aes" else 8
    rb = 0x87 if sm == "aes" else 0x1B
    L = _df_block_encrypt(key, bytes(bs), sm)

    def dbl(bb):
        n = (int.from_bytes(bb, "big") << 1) & ((1 << (bs * 8)) - 1)
        if bb[0] & 0x80:
            n ^= rb
        return n.to_bytes(bs, "big")

    k1 = dbl(L)
    return k1, dbl(k1)


def df_cmac(buffer):
    "EV1 CMAC over buffer, CBC-chained from and updating the session IV; returns the "
    "full final block (first 8 bytes are the transmitted CMAC)"
    s = DESFire_Session
    bs = 16 if s["sm"] == "aes" else 8
    if len(buffer) and len(buffer) % bs == 0:
        msg = buffer[:-bs] + _xor(buffer[-bs:], s["sk1"])
    else:
        padded = buffer + b"\x80" + bytes(bs - 1 - (len(buffer) % bs))
        msg = padded[:-bs] + _xor(padded[-bs:], s["sk2"])
    prev = s["iv"]
    for i in range(0, len(msg), bs):
        prev = _df_block_encrypt(s["key"], _xor(msg[i:i + bs], prev), s["sm"])
    s["iv"] = prev
    return prev


def _df_cbc_enc(data, iv):
    "EV1 CBC-encrypt (session cipher), returns (ciphertext, last block)"
    s = DESFire_Session
    bs = len(iv)
    out, prev = b"", iv
    for i in range(0, len(data), bs):
        prev = _df_block_encrypt(s["key"], _xor(data[i:i + bs], prev), s["sm"])
        out += prev
    return out, prev


def _df_cbc_dec(data, iv):
    "EV1 CBC-decrypt (session cipher), returns (plaintext, last cipher block)"
    s = DESFire_Session
    bs = len(iv)
    out, prev = b"", iv
    for i in range(0, len(data), bs):
        blk = data[i:i + bs]
        out += _xor(_df_block_decrypt(s["key"], blk, s["sm"]), prev)
        prev = blk
    return out, prev


def crc16a(data):
    "ISO 14443-A CRC16 (poly 0x8408, init 0x6363) - DESFire D40 legacy comms CRC"
    crc = 0x6363
    for b in data:
        b ^= crc & 0xFF
        b = (b ^ (b << 4)) & 0xFF
        crc = ((crc >> 8) ^ (b << 8) ^ (b << 3) ^ (b >> 4)) & 0xFFFF
    return crc


def desfire_des_session_key(rnda, rndb, keylen):
    "DESFire (3)DES session key from the nonces, sized to the key type"
    if keylen == 8:                                  # DES
        return rnda[0:4] + rndb[0:4]
    if keylen == 16:                                 # 2K3DES
        return rnda[0:4] + rndb[0:4] + rnda[4:8] + rndb[4:8]
    # 3K3DES (16-byte nonces)
    return (rnda[0:4] + rndb[0:4] + rnda[6:10] + rndb[6:10]
            + rnda[12:16] + rndb[12:16])

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
    print("        AUTH [<SCHEME>] <KEYNO> <KEY> [<IV>]            Authenticate. SCHEME = AES (default, 0xAA) | LEGACY/DES/3DES")
    print("                                                        (0x0A native) | ISO (0x1A). KEY = hex (8/16/24 bytes; 16 for")
    print("                                                        AES) or 0 (all-zero factory default). AES only: optional")
    print("                                                        IV = AUTO (default, ek(RndB)) | ZERO | 32 hex")
    print("        KEYSETTINGS                                     GetKeySettings (settings, key count, key type)")
    print("        KEYVERSION <KEYNO>                              GetKeyVersion")
    print("        FILEIDS                                         GetFileIDs")
    print("        ISOFILEIDS                                      GetISOFileIDs (2-byte ISO FIDs)")
    print("        FILESETTINGS <FILENO>                           GetFileSettings (type, comm, access rights, size)")
    print("        READ <FILENO> <OFFSET> <LENGTH>                 ReadData (hex; LENGTH 0 = whole file)")
    print("        GETVALUE <FILENO>                               GetValue (value file)")
    print("        GETCARDUID                                      GetCardUID - the real UID (needs a session)")
    print("        RECORDS <FILENO> <OFFSET> <NUM>                 ReadRecords (hex; NUM 0 = all)")
    print("        CMD <INS> <DATA>                                raw native command (INS hex; DATA hex or 0 for none)")
    print("        SESSION                                         show the authenticated-session state carried over this run")
    print("       -- create / modify (need a session; data wrapped per the file's comm mode: plain/MACed/enciphered) --")
    print("        CREATEAPP <AID> <KEYSETTINGS> <NKEYS>           CreateApplication (AID MSB-first)")
    print("        DELETEAPP <AID>                                 DeleteApplication")
    print("        CREATEFILE <FNO> <COMM> <AR> <SIZE>             CreateStdDataFile (COMM 00/01/03; AR 4 hex rd/wr/rw/chg)")
    print("        CREATEBACKUP <FNO> <COMM> <AR> <SIZE>           CreateBackupDataFile (transactional; COMMIT after WRITE)")
    print("        CREATEVALUE <FNO> <COMM> <AR> <LO> <HI> <VAL> <LCR>  CreateValueFile (amounts hex)")
    print("        CREATERECORD <FNO> <COMM> <AR> <RECSIZE> <MAX> <LINEAR|CYCLIC>  CreateRecordFile")
    print("        DELETEFILE <FNO>                                DeleteFile")
    print("        WRITE <FNO> <OFFSET> <DATA>                     WriteData (DATA hex)")
    print("        WRITEREC <FNO> <OFFSET> <DATA>                  WriteRecord (DATA hex)")
    print("        CREDIT <FNO> <AMOUNT>  /  DEBIT <FNO> <AMOUNT>  value-file credit/debit (then COMMIT)")
    print("        LIMITEDCREDIT <FNO> <AMOUNT>                    value-file limited credit (needs lcr enabled; then COMMIT)")
    print("        CHANGEKEY <KEYNO> <NEWKEY> [<OLDKEY>]           ChangeKey (OLDKEY needed to change a key != the session's)")
    print("        CHANGEKEYSETTINGS <SETTINGS>                    ChangeKeySettings (enciphered)")
    print("        CHANGEFILESETTINGS <FNO> <COMM> <AR>            ChangeFileSettings (enciphered)")
    print("        COMMIT  /  ABORT                                Commit/AbortTransaction")
    print("        CLEARREC <FNO>                                  ClearRecordFile (then COMMIT)")
    print("        FORMAT                                          FormatPICC - wipes ALL applications")
    print("        SETCONFIG <OPTION> <DATA>                       SetConfiguration (enciphered). OPTION 00 = PICC config:")
    print("                                                        DATA 00 none, 01 disable-format, 02 ENABLE RANDOM UID")
    print("                                                        (bit1 is PERMANENT - cannot be undone)")
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
card.info("rfidiot-cli v3.1h")

# globals
Mifare_Key = None
Mifare_KeyType = None
Mifare_KeyA = None
Mifare_KeyB = None

# DESFire authenticated-session state. The card stays authenticated for the rest
# of the run (one open connection / RF session - the same reason chained 91AF
# commands work), so OUR derived session key, IV and command counter must persist
# across main-loop iterations too. They live here at module scope, not in the
# per-command DESFIRE block (which re-runs every iteration). SELECT (changing
# application) and a failed/first AUTH reset them.
DESFire_Session = {
    "key": None,        # session key (bytes) - None until a successful AUTH
    "type": None,       # "AES" (legacy/ISO DES still TODO)
    "keyno": None,      # authenticated key number (hex str)
    "aid": "000000",    # currently selected AID (MSB-first); 000000 = PICC master
    "iv": None,         # running CBC IV for enciphered comms (bytes)
    "cmdctr": 0,        # command counter (EV2 secure messaging)
    "sm": None,         # secure-messaging scheme: "legacy" (0x0A) | "iso" (0x1A) | "aes" (0xAA)
    "sk1": None,        # EV1 CMAC subkeys (new SM)
    "sk2": None,
    "authed": False,
}


def desfire_reset_session(aid=None):
    "drop any authenticated session (new AUTH, failed AUTH, or app change)"
    DESFire_Session["key"] = None
    DESFire_Session["type"] = None
    DESFire_Session["keyno"] = None
    DESFire_Session["iv"] = None
    DESFire_Session["cmdctr"] = 0
    DESFire_Session["sm"] = None
    DESFire_Session["sk1"] = None
    DESFire_Session["sk2"] = None
    DESFire_Session["authed"] = False
    if aid is not None:
        DESFire_Session["aid"] = aid


def df_legacy_encipher(payload):
    "legacy enciphered SEND: E(payload || CRC16(payload) || zero-pad) under session key"
    crc = crc16a(payload)
    p = payload + bytes([crc & 0xFF, (crc >> 8) & 0xFF])
    if len(p) % 8:
        p += bytes(8 - len(p) % 8)
    out, _ = tdes_cbc(DESFire_Session["key"], p, bytes(8), decrypt=False, legacy=True)
    return out


def df_legacy_decipher(enc):
    "legacy enciphered RECEIVE: decipher, then locate+verify the CRC16 (search, as the "
    "CRC can fall anywhere before the zero padding). Returns (data, ok)."
    if not enc or len(enc) % 8:
        return b"", False
    plain, _ = tdes_cbc(DESFire_Session["key"], enc, bytes(8), decrypt=True, legacy=True)
    # data = plain[:n], CRC16 = plain[n:n+2], then zero padding. Search LOW->HIGH: a
    # split before the true data end is impossible because real (non-zero) data would
    # remain in the "must be zero padding" tail, so the first match is the real one.
    for n in range(0, len(plain) - 1):
        crc = crc16a(plain[:n])
        if plain[n:n + 2] == bytes([crc & 0xFF, (crc >> 8) & 0xFF]) and \
           all(b == 0 for b in plain[n + 2:]):
            return plain[:n], True
    return plain, False


def df_legacy_mac(payload):
    "legacy 4-byte CBC-MAC: standard-CBC-encrypt (session key, IV=0) the zero-padded "
    "payload; MAC = first 4 bytes of the final cipher block"
    p = payload + (bytes(8 - len(payload) % 8) if len(payload) % 8 else b"")
    if not p:
        p = bytes(8)
    out, _ = tdes_cbc(DESFire_Session["key"], p, bytes(8), decrypt=False, legacy=False)
    return out[-8:-4]

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
        COMM_NAME = {0: "plain", 1: "MACed", 3: "enciphered"}
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

        def df_raw(ins, data=""):
            "send one native command over the 7816 wrapping; return (data_hex, sw_hex)"
            if data:
                card.send_apdu("", "", "", "", "90", ins, "00", "00", "%02X" % (len(data) // 2), data, "00")
            else:
                card.send_apdu("", "", "", "", "90", ins, "00", "00", "", "", "00")
            return card.data.upper(), card.errorcode.upper()

        def df_newsm():
            "True when an EV1 'new' secure-messaging (CMAC) session is active"
            return DESFire_Session["authed"] and DESFire_Session["sm"] in ("aes", "iso")

        def df_apdu(ins, data=""):
            "send a command; in an EV1 session apply the CMAC chain (plain command -"
            "CMAC advances the IV but is not appended - and verify the response CMAC)."
            if ins != "AF" and df_newsm():
                df_cmac(bytes([int(ins, 16)]) + bytes.fromhex(data))   # advance IV
                d, sw = df_raw(ins, data)
                return df_cmac_check(d, sw)
            return df_raw(ins, data)

        def df_cmac_check(d, sw):
            "strip+verify the 8-byte response CMAC the card appends on a 9100/91AF reply, "
            "advancing the session IV in step. A command that returns an ERROR status "
            "desynchronises the EV1 channel (the card's IV handling on error differs and "
            "isn't yet mirrored here), so we drop the session and tell the user to re-AUTH "
            "rather than emit a confusing 91AE cascade. (Error-path IV handling: TODO.)"
            if df_newsm() and sw in ("9100", "91AF"):
                if len(d) >= 16:
                    raw = bytes.fromhex(d)
                    payload, mac = raw[:-8], raw[-8:]
                    expect = df_cmac(payload + bytes([int(sw[2:4], 16)]))[:8]
                    if mac != expect:
                        print("    [new-SM response CMAC verify FAILED]")
                    return payload.hex().upper(), sw
                return d, sw
            if df_newsm() and sw.startswith("91") and sw not in ("9100", "91AF"):
                print("    (EV1 secure channel desynchronised by this error - re-AUTH to continue)")
                desfire_reset_session(DESFire_Session["aid"])
            return d, sw

        def df_full(ins, data=""):
            "send a command and gather all chained (91AF) frames: (all_data, final_sw)"
            d, sw = df_apdu(ins, data)
            while sw == "91AF":
                more, sw = df_apdu("AF")
                d += more
            return d, sw

        def df_status(sw):
            # a real DESFire response is always 91xx; anything else is a transport
            # failure (e.g. PN00 = libnfc transceive failed - no tag activated)
            if sw in DF_STATUS:
                return "%s (%s)" % (sw, DF_STATUS[sw])
            if not sw.startswith("91"):
                return "%s (no DESFire response - SELECT a tag first; is one present?)" % sw
            return "%s (unknown)" % sw

        def df_rev_aid(aid):
            "AID is 3 bytes LSB-first on the wire; show/accept it MSB-first (F53630)"
            return aid[4:6] + aid[2:4] + aid[0:2]

        def _ishex(t):
            return len(t) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in t)

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
            # selecting an application always drops any authenticated session
            if sw == "9100":
                desfire_reset_session(aid)
            continue
        if dfcommand == "AUTH":
            # authenticate. Optional scheme keyword (default AES):
            #   LEGACY / DES / 3DES -> 0x0A native DES/2K3DES/3K3DES (D40 "inverted" CBC)
            #   ISO                 -> 0x1A ISO 2K3DES/3K3DES (standard CBC)
            #   AES                 -> 0xAA AuthenticateAES
            # key length (8/16/24, or 16 for AES) picks DES/2K3DES/3K3DES; key "0"
            # = the all-zero factory default (DES for the DES keyword, else 16-byte).
            import os as _os
            SCHEMES = {"AES": "AES", "LEGACY": "LEGACY", "DES": "LEGACY",
                       "3DES": "LEGACY", "ISO": "ISO"}
            rawscheme = ""
            if args and args[-1].upper() in SCHEMES:
                rawscheme = args.pop().upper()
            scheme = SCHEMES.get(rawscheme, "AES")
            keyno = args.pop().upper().zfill(2)          # key number, e.g. 00 (accept 0)
            keyhex = args.pop().upper()                   # hex key, or 0 for all-zero
            if keyhex in ("0", "ZERO"):
                keyhex = "00" * (8 if rawscheme == "DES" else 16)

            # optional response-IV override (AES only, chain-safe peek) for testing
            ivmode = "AUTO"
            if scheme == "AES" and args and (args[-1].upper() in ("AUTO", "ZERO")
                                             or (len(args[-1]) == 32 and _ishex(args[-1]))):
                ivmode = args.pop().upper()
            try:
                key = bytes.fromhex(keyhex)
            except ValueError:
                print("  AUTH: key must be hex or 0")
                continue
            # a new authentication attempt invalidates any prior session
            desfire_reset_session()

            if scheme == "AES":
                from Crypto.Cipher import AES
                if len(key) != 16:
                    print("  AUTH AES: key must be 16 bytes (32 hex) or 0")
                    continue
                d, sw = df_apdu("AA", keyno)              # AuthenticateAES, key <keyno>
                if sw != "91AF" or len(d) != 32:
                    print("  AuthenticateAES key %s: %s (no challenge - AES key?)" % (keyno, df_status(sw)))
                    continue
                ek = bytes.fromhex(d)
                rndb = AES.new(key, AES.MODE_CBC, bytes(16)).decrypt(ek)
                rndb_rot = rotate_left(rndb)
                rnda = _os.urandom(16)
                enc_iv = ek if ivmode == "AUTO" else (bytes(16) if ivmode == "ZERO" else bytes.fromhex(ivmode))
                token = AES.new(key, AES.MODE_CBC, enc_iv).encrypt(rnda + rndb_rot)
                d, sw = df_apdu("AF", token.hex().upper())
                which = "all-zero key" if key == bytes(16) else "key " + keyhex
                ivdesc = {"AUTO": "IV=ek(RndB)", "ZERO": "IV=0"}.get(ivmode, "IV=" + ivmode)
                print("  AuthenticateAES key %s with %s (%s): %s" % (keyno, which, ivdesc, df_status(sw)))
                if sw == "9100" and len(d) == 32:
                    rnda_back = AES.new(key, AES.MODE_CBC, token[-16:]).decrypt(bytes.fromhex(d))
                    if rnda_back == rotate_left(rnda):
                        sesskey = desfire_aes_session_key(rnda, rndb)
                        sk1, sk2 = df_cmac_subkeys(sesskey, "aes")
                        DESFire_Session.update(key=sesskey, type="AES", keyno=keyno,
                                               iv=bytes(16), cmdctr=0, sm="aes",
                                               sk1=sk1, sk2=sk2, authed=True)
                        print("    *** AUTH OK - the key is %s ***" % keyhex)
                        print("    session established: RndA' verified, AES session key %s" % sesskey.hex().upper())
                    else:
                        print("    *** AUTH OK (9100) but RndA' MISMATCH - session NOT established ***")
                        print("      expected %s got %s" % (rotate_left(rnda).hex().upper(), rnda_back.hex().upper()))
                else:
                    print("    auth failed (as expected unless %s is the real key)" % which)
                continue

            # (3)DES: LEGACY (0x0A, D40 inverted CBC) or ISO (0x1A, standard CBC)
            if len(key) not in (8, 16, 24):
                print("  AUTH %s: key must be 8/16/24 bytes (DES/2K3DES/3K3DES) or 0" % scheme)
                continue
            legacy = scheme == "LEGACY"
            ins = "0A" if legacy else "1A"
            ktype = {8: "DES", 16: "2K3DES", 24: "3K3DES"}[len(key)]
            label = "AuthenticateLegacy(0A)" if legacy else "AuthenticateISO(1A)"
            d, sw = df_apdu(ins, keyno)
            if sw != "91AF" or len(d) not in (16, 32):   # 8- or 16-byte challenge
                print("  %s %s key %s: %s (no challenge - wrong key type?)" % (label, ktype, keyno, df_status(sw)))
                continue
            ek = bytes.fromhex(d)
            rndb, _ = tdes_cbc(key, ek, bytes(8), decrypt=True, legacy=legacy)
            rndb_rot = rotate_left(rndb)
            rnda = _os.urandom(len(rndb))
            # D40 legacy resets IV=0 per message; ISO chains from the last challenge
            # block (ek[-8:], which == ek for a 1-block 2K3DES challenge but is the
            # 2nd block for a 16-byte 3K3DES challenge)
            tok_iv = bytes(8) if legacy else ek[-8:]
            token, lastc = tdes_cbc(key, rnda + rndb_rot, tok_iv, decrypt=False, legacy=legacy)
            d, sw = df_apdu("AF", token.hex().upper())
            which = "all-zero key" if key == bytes(len(key)) else "key " + keyhex
            print("  %s %s key %s with %s: %s" % (label, ktype, keyno, which, df_status(sw)))
            if sw == "9100" and len(d) == len(ek) * 2:
                # D40 legacy resets IV=0 for each message; ISO chains (resp IV = last
                # token cipher block, like AES)
                resp_iv = bytes(8) if legacy else lastc
                rnda_back, _ = tdes_cbc(key, bytes.fromhex(d), resp_iv, decrypt=True, legacy=legacy)
                if rnda_back == rotate_left(rnda):
                    sesskey = desfire_des_session_key(rnda, rndb, len(key))
                    sk1, sk2 = (None, None) if legacy else df_cmac_subkeys(sesskey, "iso")
                    DESFire_Session.update(key=sesskey, type=ktype, keyno=keyno,
                                           iv=bytes(8), cmdctr=0,
                                           sm=("legacy" if legacy else "iso"),
                                           sk1=sk1, sk2=sk2, authed=True)
                    print("    *** AUTH OK - the key is %s ***" % keyhex)
                    print("    session established: RndA' verified, %s session key %s" % (ktype, sesskey.hex().upper()))
                else:
                    print("    *** AUTH OK (9100) but RndA' MISMATCH - session NOT established ***")
                    print("      expected %s got %s" % (rotate_left(rnda).hex().upper(), rnda_back.hex().upper()))
            else:
                print("    auth failed (as expected unless %s is the real key)" % which)
            continue

        def le3(x):
            "3-byte little-endian hex from a hex/int string (offsets, lengths, values)"
            n = int(x, 16)
            return "%02X%02X%02X" % (n & 0xFF, (n >> 8) & 0xFF, (n >> 16) & 0xFF)

        def le4(x):
            "4-byte little-endian hex (value-file amounts)"
            n = int(x, 16)
            return "%02X%02X%02X%02X" % (n & 0xFF, (n >> 8) & 0xFF, (n >> 16) & 0xFF, (n >> 24) & 0xFF)

        def ar_le(ar):
            "access-rights 4-hex (read/write/rw/change, MSB-first) -> 2 bytes LSB-first on wire"
            ar = ar.upper().zfill(4)
            return ar[2:4] + ar[0:2]

        def ar_name(n):
            return {0xE: "free", 0xF: "never"}.get(n, "key %X" % n)

        def df_comm(fileno):
            "file comm mode (0 plain / 1 MACed / 3 enciphered) from GetFileSettings"
            d, sw = df_apdu("F5", fileno)
            return int(d[2:4], 16) if (sw == "9100" and len(d) >= 4) else 0

        def df_sm_ok(comm):
            "True if we can wrap for this comm mode (free plain files need no session)"
            if DESFire_Session["authed"] or comm == 0:
                return True
            print("    MACed/enciphered files need a session (AUTH ...)")
            return False

        def df_send(ins, header, payload, comm):
            "send a data command, wrapping <payload> per comm mode (header stays plain)"
            if df_newsm():                             # EV1 new secure messaging
                buf = bytes([int(ins, 16)]) + bytes.fromhex(header) + payload
                if comm == 3:                          # enciphered: E(payload||CRC32||pad)
                    s = DESFire_Session
                    bs = 16 if s["sm"] == "aes" else 8
                    plain = payload + crc32_jam(buf).to_bytes(4, "little")
                    if len(plain) % bs:
                        plain += bytes(bs - len(plain) % bs)
                    enc, s["iv"] = _df_cbc_enc(plain, s["iv"])
                    d, sw = df_raw(ins, header + enc.hex().upper())
                else:                                  # plain / MACed: CMAC advances IV
                    cm = df_cmac(buf)
                    body = header + payload.hex().upper()
                    if comm == 1:
                        body += cm[:8].hex().upper()
                    d, sw = df_raw(ins, body)
                return df_cmac_check(d, sw)            # verify+strip the response CMAC
            # legacy (D40) comms
            if comm == 3:
                body = df_legacy_encipher(payload).hex().upper()
            elif comm == 1:
                body = payload.hex().upper() + df_legacy_mac(payload).hex().upper()
            else:
                body = payload.hex().upper()
            return df_full(ins, header + body)

        def df_read(ins, header, comm):
            "send a read command and return the (sw, unwrapped-payload) per comm mode"
            if df_newsm():
                df_cmac(bytes([int(ins, 16)]) + bytes.fromhex(header))   # advance IV
                d, sw = df_raw(ins, header)
                while sw == "91AF":                    # gather chained frames (small files: 1)
                    more, sw = df_raw("AF")
                    d += more
                return df_recv(d, sw, comm)
            d, sw = df_full(ins, header)
            return df_recv(d, sw, comm)

        def df_recv(data, sw, comm):
            "unwrap a response <data> per comm mode; returns (payload_hex, sw, note)"
            if sw != "9100" or not data:
                return data, sw, ""
            raw = bytes.fromhex(data)
            if df_newsm():
                s = DESFire_Session
                if comm == 3:                          # enciphered: decipher, find CRC32
                    plain, s["iv"] = _df_cbc_dec(raw, s["iv"])
                    for n in range(0, len(plain) - 3):
                        if crc32_jam(plain[:n] + b"\x00") == int.from_bytes(plain[n:n + 4], "little"):
                            tail = plain[n + 4:]
                            if all(b == 0 for b in tail) or (tail[:1] == b"\x80" and all(b == 0 for b in tail[1:])):
                                return plain[:n].hex().upper(), sw, ""
                    return plain.hex().upper(), sw, "  [CRC32 FAIL]"
                # plain / MACed response: payload || CMAC8 (over payload||status)
                if len(raw) < 8:
                    return data, sw, "  [CMAC: short]"
                payload, mac = raw[:-8], raw[-8:]
                expect = df_cmac(payload + bytes([int(sw[2:4], 16)]))[:8]
                return payload.hex().upper(), sw, ("" if mac == expect else "  [CMAC FAIL]")
            # legacy (D40) comms
            if comm == 3:
                pl, ok = df_legacy_decipher(raw)
                return pl.hex().upper(), sw, ("" if ok else "  [CRC FAIL]")
            if comm == 1:
                if len(raw) < 4:
                    return data, sw, "  [MAC: short]"
                body, mac = raw[:-4], raw[-4:]
                return body.hex().upper(), sw, ("" if df_legacy_mac(body) == mac else "  [MAC FAIL]")
            return data, sw, ""

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
            keyno = args.pop().upper().zfill(2)
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
        if dfcommand == "ISOFILEIDS":              # GetISOFileIDs (0x61): 2-byte ISO FIDs
            d, sw = df_full("61")
            if sw != "9100":
                print("  GetISOFileIDs: " + df_status(sw)); continue
            # ISO FIDs are 2 bytes each, LSB-first on the wire; show MSB-first
            fids = [d[i + 2:i + 4] + d[i:i + 2] for i in range(0, len(d), 4)]
            print("  ISO FIDs (%d): %s" % (len(fids), " ".join(fids) or "(none)"))
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
            fileno = args.pop().upper().zfill(2)
            comm = df_comm(fileno)
            if not df_sm_ok(comm):
                continue
            d, sw, note = df_read("6C", fileno, comm)
            if sw == "9100" and len(d) >= 8:
                print("  Value file %s = %d (%s comm)%s" % (
                    fileno, int(d[6:8] + d[4:6] + d[2:4] + d[0:2], 16), COMM_NAME[comm], note))
            else:
                print("  GetValue file %s: %s" % (fileno, df_status(sw)))
            continue
        if dfcommand == "READ":                    # ReadData (0xBD) <fileno> <offset> <length>
            fileno = args.pop().upper().zfill(2)
            off = args.pop()
            length = args.pop()        # 0 = whole file
            comm = df_comm(fileno)
            if not df_sm_ok(comm):
                continue
            d, sw, note = df_read("BD", fileno + le3(off) + le3(length), comm)
            print("  ReadData file %s off %s len %s (%s comm): %s%s" % (
                fileno, off, length, COMM_NAME[comm], df_status(sw), note))
            if d:
                print("    %s  %s" % (d, ReadablePrintHex(d)))
            continue
        if dfcommand == "RECORDS":                 # ReadRecords (0xBB) <fileno> <offset> <num>
            fileno = args.pop().upper().zfill(2)
            off = args.pop()
            num = args.pop()           # 0 = all records
            comm = df_comm(fileno)
            if not df_sm_ok(comm):
                continue
            d, sw, note = df_read("BB", fileno + le3(off) + le3(num), comm)
            print("  ReadRecords file %s off %s num %s (%s comm): %s%s" % (
                fileno, off, num, COMM_NAME[comm], df_status(sw), note))
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
        if dfcommand == "CHANGEKEY":               # ChangeKey (0xC4) - needs a session
            # CHANGEKEY <keyno> <newkey> [<oldkey>]. Same-key change (keyno == the
            # authenticated key): plaintext = NewKey || CRC16(NewKey). Different-key
            # change (needs <oldkey>): plaintext = (NewKey XOR OldKey) ||
            # CRC16(NewKey XOR OldKey) || CRC16(NewKey). Zero-padded, enciphered under
            # the SESSION key (legacy inverted CBC, IV=0). Legacy (3)DES session only.
            ck_keyno = args.pop().upper().zfill(2)
            ck_new = args.pop().upper()
            s = DESFire_Session
            if ck_new in ("0", "ZERO"):
                ck_new = "00" * (24 if s["type"] == "3K3DES" else 16)
            # chain-safe peek for an optional old key (hex of 8/16/24 bytes)
            ck_old = None
            if args and len(args[-1]) in (16, 32, 48) and _ishex(args[-1]):
                ck_old = args.pop().upper()
            if not s["authed"]:
                print("  CHANGEKEY: authenticate first (DESFIRE AUTH ...)")
                continue
            try:
                newkey = bytes.fromhex(ck_new)
                oldkey = bytes.fromhex(ck_old) if ck_old else None
            except ValueError:
                print("  CHANGEKEY: key must be hex or 0")
                continue
            samekey = int(ck_keyno, 16) == int(s["keyno"], 16)
            if not samekey and (oldkey is None or len(oldkey) != len(newkey)):
                print("  CHANGEKEY: changing a different key needs <oldkey> of the same length")
                continue
            hdr = bytes([0xC4, int(ck_keyno, 16)])
            if df_newsm():
                # EV1: CRC32 over C4||keyno||newkey[||version]; AES carries a version byte;
                # enciphered under the session, IV chaining. Different-key adds CRC32(newkey).
                bs = 16 if s["sm"] == "aes" else 8
                ver = b"\x00" if s["sm"] == "aes" else b""
                if samekey:
                    body = newkey + ver
                    crypto_plain = body + crc32_jam(hdr + body).to_bytes(4, "little")
                else:
                    body = _xor(newkey, oldkey) + ver
                    crypto_plain = (body + crc32_jam(hdr + body).to_bytes(4, "little")
                                    + crc32_jam(newkey).to_bytes(4, "little"))
                if len(crypto_plain) % bs:
                    crypto_plain += bytes(bs - len(crypto_plain) % bs)
                enc, s["iv"] = _df_cbc_enc(crypto_plain, s["iv"])
                d, sw = df_raw("C4", ck_keyno + enc.hex().upper())
                if not samekey:
                    d, sw = df_cmac_check(d, sw)      # session survives -> check response CMAC
                label = s["sm"]
            else:
                # legacy (D40): CRC16 over newkey; enciphered inverted-CBC, IV=0
                if samekey:
                    plain = newkey + crc16a(newkey).to_bytes(2, "little")
                else:
                    xored = _xor(newkey, oldkey)
                    plain = (xored + crc16a(xored).to_bytes(2, "little")
                             + crc16a(newkey).to_bytes(2, "little"))
                if len(plain) % 8:
                    plain += bytes(8 - len(plain) % 8)
                enc, _ = tdes_cbc(s["key"], plain, bytes(8), decrypt=False, legacy=True)
                d, sw = df_apdu("C4", ck_keyno + enc.hex().upper())
                label = "legacy"
            print("  ChangeKey(%s) key %s -> %s (%s): %s" % (
                label, ck_keyno, ck_new, "same key" if samekey else "diff key", df_status(sw)))
            if sw == "9100":
                print("    *** key changed ***")
                if samekey:
                    desfire_reset_session()      # changing our own key drops the session
            continue
        if dfcommand == "CREATEAPP":               # CreateApplication (0xCA)
            aid = args.pop().upper()                # MSB-first
            ksett = args.pop().upper().zfill(2)     # key settings byte (e.g. 0F)
            nkeys = args.pop().upper().zfill(2)     # number of keys (+ 0x40=3K3DES / 0x80=AES)
            d, sw = df_apdu("CA", df_rev_aid(aid) + ksett + nkeys)
            print("  CreateApplication %s (keysettings %s, %s keys): %s" % (aid, ksett, nkeys, df_status(sw)))
            continue
        if dfcommand == "DELETEAPP":               # DeleteApplication (0xDA)
            aid = args.pop().upper()
            d, sw = df_apdu("DA", df_rev_aid(aid))
            print("  DeleteApplication %s: %s" % (aid, df_status(sw)))
            continue
        if dfcommand == "CREATEFILE":              # CreateStdDataFile (0xCD) <fno> <comm> <ar> <size>
            fileno = args.pop().upper().zfill(2)
            comm = args.pop().upper().zfill(2)      # 00 plain / 01 MACed / 03 enciphered
            ar = args.pop().upper()                 # 4 hex: read/write/rw/change (E=free F=never)
            size = args.pop()
            d, sw = df_apdu("CD", fileno + comm + ar_le(ar) + le3(size))
            print("  CreateStdDataFile %s comm %s AR %s size %s: %s" % (fileno, comm, ar.zfill(4), size, df_status(sw)))
            continue
        if dfcommand == "CREATEBACKUP":            # CreateBackupDataFile (0xCB) <fno> <comm> <ar> <size>
            fileno = args.pop().upper().zfill(2)
            comm = args.pop().upper().zfill(2)
            ar = args.pop().upper()
            size = args.pop()
            d, sw = df_apdu("CB", fileno + comm + ar_le(ar) + le3(size))
            print("  CreateBackupDataFile %s comm %s AR %s size %s: %s" % (fileno, comm, ar.zfill(4), size, df_status(sw)))
            continue
        if dfcommand == "CREATEVALUE":             # CreateValueFile (0xCC) <fno> <comm> <ar> <lo> <hi> <val> <lcr>
            fileno = args.pop().upper().zfill(2)
            comm = args.pop().upper().zfill(2)
            ar = args.pop().upper()
            lo = args.pop(); hi = args.pop(); val = args.pop(); lcr = args.pop().upper().zfill(2)
            d, sw = df_apdu("CC", fileno + comm + ar_le(ar) + le4(lo) + le4(hi) + le4(val) + lcr)
            print("  CreateValueFile %s comm %s AR %s [%s..%s]=%s lcr %s: %s" % (
                fileno, comm, ar.zfill(4), lo, hi, val, lcr, df_status(sw)))
            continue
        if dfcommand == "CREATERECORD":            # Create{Linear,Cyclic}RecordFile (0xC1/0xC0)
            fileno = args.pop().upper().zfill(2)
            comm = args.pop().upper().zfill(2)
            ar = args.pop().upper()
            recsize = args.pop(); maxrec = args.pop()
            kind = args.pop().upper()               # LINEAR or CYCLIC (required, chain-safe)
            ins = "C0" if kind == "CYCLIC" else "C1"
            d, sw = df_apdu(ins, fileno + comm + ar_le(ar) + le3(recsize) + le3(maxrec))
            print("  Create%sRecordFile %s comm %s AR %s recsize %s max %s: %s" % (
                kind.capitalize(), fileno, comm, ar.zfill(4), recsize, maxrec, df_status(sw)))
            continue
        if dfcommand == "DELETEFILE":              # DeleteFile (0xDF)
            fileno = args.pop().upper().zfill(2)
            d, sw = df_apdu("DF", fileno)
            print("  DeleteFile %s: %s" % (fileno, df_status(sw)))
            continue
        if dfcommand == "WRITE":                   # WriteData (0x3D) <fno> <off> <data-hex>
            fileno = args.pop().upper().zfill(2)
            off = args.pop()
            wdata = bytes.fromhex(args.pop())
            comm = df_comm(fileno)
            if not df_sm_ok(comm):
                continue
            header = fileno + le3(off) + le3("%X" % len(wdata))
            d, sw = df_send("3D", header, wdata, comm)
            print("  WriteData file %s off %s len %d (%s comm): %s" % (
                fileno, off, len(wdata), COMM_NAME[comm], df_status(sw)))
            continue
        if dfcommand == "WRITEREC":                # WriteRecord (0x3B) <fno> <off> <data-hex>
            fileno = args.pop().upper().zfill(2)
            off = args.pop()
            wdata = bytes.fromhex(args.pop())
            comm = df_comm(fileno)
            if not df_sm_ok(comm):
                continue
            header = fileno + le3(off) + le3("%X" % len(wdata))
            d, sw = df_send("3B", header, wdata, comm)
            print("  WriteRecord file %s off %s len %d (%s comm): %s" % (
                fileno, off, len(wdata), COMM_NAME[comm], df_status(sw)))
            continue
        if dfcommand == "CREDIT":                  # Credit (0x0C) <fno> <amount>
            fileno = args.pop().upper().zfill(2)
            amt = args.pop()
            comm = df_comm(fileno)
            if not df_sm_ok(comm):
                continue
            d, sw = df_send("0C", fileno, bytes.fromhex(le4(amt)), comm)
            print("  Credit file %s += %s (%s comm): %s" % (fileno, amt, COMM_NAME[comm], df_status(sw)))
            continue
        if dfcommand == "DEBIT":                   # Debit (0xDC) <fno> <amount>
            fileno = args.pop().upper().zfill(2)
            amt = args.pop()
            comm = df_comm(fileno)
            if not df_sm_ok(comm):
                continue
            d, sw = df_send("DC", fileno, bytes.fromhex(le4(amt)), comm)
            print("  Debit file %s -= %s (%s comm): %s" % (fileno, amt, COMM_NAME[comm], df_status(sw)))
            continue
        if dfcommand == "LIMITEDCREDIT":           # LimitedCredit (0x1C) <fno> <amount>
            fileno = args.pop().upper().zfill(2)
            amt = args.pop()
            comm = df_comm(fileno)
            if not df_sm_ok(comm):
                continue
            d, sw = df_send("1C", fileno, bytes.fromhex(le4(amt)), comm)
            print("  LimitedCredit file %s += %s (%s comm): %s" % (fileno, amt, COMM_NAME[comm], df_status(sw)))
            continue
        if dfcommand == "COMMIT":                  # CommitTransaction (0xC7)
            d, sw = df_apdu("C7")
            print("  CommitTransaction: " + df_status(sw))
            continue
        if dfcommand == "ABORT":                   # AbortTransaction (0xA7)
            d, sw = df_apdu("A7")
            print("  AbortTransaction: " + df_status(sw))
            continue
        if dfcommand == "CLEARREC":                # ClearRecordFile (0xEB) <fno>
            fileno = args.pop().upper().zfill(2)
            d, sw = df_apdu("EB", fileno)
            print("  ClearRecordFile %s: %s" % (fileno, df_status(sw)))
            continue
        if dfcommand == "FORMAT":                  # FormatPICC (0xFC) - wipes ALL applications
            d, sw = df_apdu("FC")
            print("  FormatPICC (wipes all apps): " + df_status(sw))
            continue
        if dfcommand == "SETCONFIG":               # SetConfiguration (0x5C) <option> <data-hex>
            # the data is enciphered (legacy CRC16 / EV1 CRC32) under the PICC-master
            # session. Option 00 = PICC config byte: bit0 disable-format, bit1 ENABLE
            # RANDOM UID (PERMANENT!).
            opt = args.pop().upper().zfill(2)
            cfg = bytes.fromhex(args.pop())
            if not DESFire_Session["authed"]:
                print("  SETCONFIG: authenticate (PICC master) first")
                continue
            if opt == "00" and cfg and (cfg[0] & 0x02):
                print("  SETCONFIG: option 00 bit1 ENABLES RANDOM UID and is IRREVERSIBLE.")
            d, sw = df_send("5C", opt, cfg, 3)
            print("  SetConfiguration opt %s data %s: %s" % (opt, cfg.hex().upper(), df_status(sw)))
            continue
        if dfcommand == "CHANGEKEYSETTINGS":       # ChangeKeySettings (0x54) <settings>
            newset = args.pop().upper().zfill(2)
            if not DESFire_Session["authed"]:
                print("  CHANGEKEYSETTINGS: authenticate first")
                continue
            d, sw = df_send("54", "", bytes.fromhex(newset), 3)
            print("  ChangeKeySettings -> %s: %s" % (newset, df_status(sw)))
            continue
        if dfcommand == "CHANGEFILESETTINGS":      # ChangeFileSettings (0x5F) <fno> <comm> <ar>
            fileno = args.pop().upper().zfill(2)    # fileno stays plain; comm+AR enciphered
            comm = args.pop().upper().zfill(2)
            ar = args.pop().upper()
            if not DESFire_Session["authed"]:
                print("  CHANGEFILESETTINGS: authenticate first")
                continue
            d, sw = df_send("5F", fileno, bytes.fromhex(comm + ar_le(ar)), 3)
            print("  ChangeFileSettings %s -> comm %s AR %s: %s" % (fileno, comm, ar.zfill(4), df_status(sw)))
            continue
        if dfcommand == "GETCARDUID":              # GetCardUID (0x51) - real UID, enciphered
            if not DESFire_Session["authed"]:
                print("  GETCARDUID: authenticate first")
                continue
            uid, sw, note = df_read("51", "", 3)
            if sw == "9100":
                print("  GetCardUID (real UID): %s%s" % (uid, note))
            else:
                print("  GetCardUID: " + df_status(sw))
            continue
        if dfcommand == "SESSION":                 # show the carried-over session state
            s = DESFire_Session
            print("  DESFire session state (this run):")
            print("    selected AID : %s" % s["aid"])
            if s["authed"]:
                print("    authenticated: yes (%s key %s, %s secure messaging)" % (
                    s["type"], s["keyno"], s["sm"]))
                print("    session key  : %s" % s["key"].hex().upper())
                print("    cmd counter  : %d" % s["cmdctr"])
                print("    IV           : %s" % s["iv"].hex().upper())
            else:
                print("    authenticated: no")
            continue
        print("  Unknown DESFIRE command:", dfcommand)
        print("  commands: VERSION AIDS SELECT AUTH CHANGEKEY SESSION FREEMEM")
        print("            KEYSETTINGS KEYVERSION FILEIDS ISOFILEIDS FILESETTINGS")
        print("            GETVALUE GETCARDUID READ RECORDS DFNAMES CMD")
        print("    create/modify: CREATEAPP DELETEAPP CREATEFILE CREATEBACKUP")
        print("            CREATEVALUE CREATERECORD DELETEFILE WRITE WRITEREC")
        print("            CREDIT DEBIT LIMITEDCREDIT COMMIT ABORT CLEARREC")
        print("            CHANGEKEYSETTINGS CHANGEFILESETTINGS FORMAT SETCONFIG")
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
