# RFIDIOt python3 branch - TODO

Carried over from the 2026-09-14 session (also recorded in Claude memory).
Everything else from that session is done and pushed to `origin/python3`.

## 1. Import personal DESFire script
- RFIDIOt has **no** DESFire tool of its own (only a SAK `20` -> "MIFARE DESFIRE"
  label at `rfidiot/RFIDIOt.py:849`). `libfreefare`'s `mifare-desfire-info` is the
  interim stand-in.
- Import Adam's personal DESFire script into the repo/toolset.
- Known-good test card: genuine **MIFARE DESFire EV1 4K**, UID `044E32AA571290`
  (free directory listing without auth; app `003806` has a free-read file).

## 2. Finish the Py3 typing sweep (untested tools)
True-division `/` -> `//` (float used as index / length / APDU-Lc):
- `transit.py` L99-101, `fdxbnum.py` L103-104
- `pn532emulate.py` L126/132, `pn532mitm.py` L291/297
- `jcopsetatrhist.py` L61/62/74

`ord()`/`chr()`-on-bytes and bytearray issues:
- `jcoptool.py` L149 (`ord(bytearray)` -> `[0]`), L160 (`manufacturers[bytearray]`
  is unhashable), L156/159 (`ToBinary(...)` printed via `%s` shows bytearray repr).
  Also: needs the `pyasn1` module (add to requirements); and its RFID-style
  `card.select()` (FF CA UID) fails on contact T=0 JavaCards ("No RFID card
  present" then a failed transmit) - it should skip the RFID select for PC/SC
  contact cards. Verified a JCOP card (CPLC/9F7F readable, T=0) now talks to the
  library after the T=0 PCSC protocol fix, but jcoptool's flow still needs the
  above. (openssl/pyasn1 are only needed by jcoptool.)
- `pn532mitm.py` `send_data`/`recv_data` need socket bytes (encode on send, decode
  on recv); also the `data` -> `cdata` bug in `send_data`
- `Run_Test.py` L188 is already guarded - no fix needed

See `docs/python3-typing-audit.md` for the full list. These are serial/socket
paths that can't be hardware-tested with the current SCL3711 (libnfc) setup.

## 3. Hardware-verify (need specific cards/readers)
- MIFARE Classic `CLONE`/`WRITE` in `rfidiot-cli.py` - needs a MIFARE Classic 1k card
- `hidprox.py` H10301/H10302 decode - needs an HID Prox card via PC/SC

## 4. Grow the ChAP EMV CA key table (as cards appear)
- `ChAP.py` `CA_PUBLIC_KEYS` now holds 26 production keys across 8 schemes (Visa,
  Mastercard, Amex, CB, JCB, Discover, UnionPay, RuPay), imported from a terminal
  capkeys.cfg and each verified against its EMVCo CAPK checksum
  SHA1(RID|index|modulus|exp). Verified live so far: Visa 08/09, MC 05/06, Amex
  0F/10. Add more when a card needs them: a terminal capkeys.cfg (RID/CAPKI/EXP/
  HASH + modulus hex block), e.g. paypalobjects miura capkeys.cfg, is a good
  structured source - fetch with curl + a browser UA, then checksum-verify.
  each new key is checked against the published EMVCo CAPK checksum
  SHA1(RID|index|modulus|exp) before adding, and self-validates via the `6A..BC`
  + SHA-1 cert recovery when used.
- Companion/alias AIDs (e.g. LINK `A000000029`) have no CA keys of their own - their
  certs are signed by the primary scheme's CA. [DONE] recover_certificates() now
  falls back to searching CA keys of the same index across all RIDs and uses
  whichever validates the Issuer cert (6A..BC + hash, so a false match is
  impossible). Confirmed: a card's LINK app verifies under the Mastercard CA.

## 5. ChAP.py feature enhancements (implement in order)
Survey of what ChAP.py could do that it doesn't yet. Work these one at a time,
top to bottom.

1. **[DONE] Live card authentication (complete what `-c` starts).** `-c` now runs,
   after the cert chain, SDA + DDA/fDDA against the recovered keys:
   - **SDA** - `verify_sda()` recovers Signed Static Application Data (tag 93)
     against the recovered Issuer key, rebuilding the authenticated static data
     from the AFL offline records (SFI<=10 template-stripping rule) + the 9F4A tag
     list's AIP. VERIFIED live on an SDA-only HDFC Bank Visa (Visa CA idx 08).
   - **DDA (contact)** - `verify_dda()` sends INTERNAL AUTHENTICATE with a random
     UN via the DDOL (9F49), recovers 9F4B, verifies. VERIFIED on Visa + Amex.
   - **fDDA (contactless)** - verifies the 9F4B returned inline in the GPO. The
     Visa qVSDC hash covers UN || Amount (9F02) || Currency (5F2A) || Card
     Authentication Related Data (9F69). VERIFIED on a contactless Visa.
   Also fixed two general bugs: the GPO template body offset for long (>127-byte)
   BER lengths, and storing the AIP from a Format-1 GPO into EMVData[0x82].
2. **[DONE] Transaction log reading.** `read_transaction_log()` follows Log Entry
   (9F4D) -> SFI + count, reads the Log Format (9F4F) DOL, READ RECORDs the log SFI
   and decodes each entry (amount, currency, date, time, ATC, txn type, country via
   format_log_field). VERIFIED on a Debit Mastercard - decoded its real purchase
   history. Also added tags 9F21/9F27/9F4E to TAGS so the log labels cleanly.
3. **[DONE] Fill in the tag dictionary.** Added, with names verified against public
   EMV tag references (EFTLab/emvlab): 9F21 (Transaction Time), 9F27 (Cryptogram
   Information Data), 9F4E (Merchant Name and Location), 9F10 (Issuer Application
   Data), 9F0A (Application Selection Registered Proprietary Data), 9F5A (Application
   Program Identifier), 9F6C (Card Transaction Qualifiers), 9F6E (Form Factor
   Indicator / Third Party Data), 9F69 (Card Authentication Related Data), 9F7C
   (Customer Exclusive Data). Deliberately left as hex: DF3E (issuer-proprietary
   DFxx), 9F52 and 9F65 (conflicting cross-scheme/version definitions - a wrong name
   is worse than hex).
4. **[DONE] Bug: 0x9F66 was mislabeled** "Card Production Life Cycle" (that's 9F7F) -
   corrected to **Terminal Transaction Qualifiers (TTQ)**.
5. **[DONE] Decode Track 2 into fields** - decode_track2() splits the Track 2
   Equivalent (tag 57) into PAN / expiry / service code / discretionary, and
   decode_service_code() expands the 3-digit service code (ISO 7813). decode_cid()
   decodes 9F27 CID bits (AAC/TC/ARQC + CDA) in the TLV path, and the log shows the
   type inline, e.g. "40 (TC)". Verified live on Visa/Mastercard + unit-tested.
6. **[DONE] GENERATE AC + CDA verification** (opt-in, intrusive). `-g` sends GENERATE
   AC (ARQC + CDA requested) built from the CDOL1 with a random UN, decodes the
   response (CID/ATC/cryptogram) and verifies the returned Signed Dynamic
   Application Data (9F4B) against the recovered ICC key via _verify_sdad. This
   completes offline-auth coverage for CDA cards (the common modern type). Behind an
   explicit flag with an ATC-increment warning. VERIFIED live on a CDA Debit
   Mastercard - so SDA/DDA/fDDA/CDA are all hardware-verified now.
7. **[DONE] Enciphered offline PIN** - `-E` sends the offline PIN as RSA-enciphered
   under the recovered ICC public key (verify_pin_enciphered): GET CHALLENGE, build
   7F || PIN-block || ICC-UN || random-pad to the ICC key length, encipher, VERIFY
   with P2=0x88. Implies -c; opt-in with a PIN-Try-Counter warning. Unit-tested
   (block layout + message < modulus); live VERIFY left for the user to run with a
   real PIN (a wrong PIN can block the card).

Lower priority:
- JSON/structured output (library already has a `-j` Json global ChAP ignores).
- Final one-line card summary (scheme, masked PAN, expiry, cardholder, CVMs, auth
  result).
- Load `CA_PUBLIC_KEYS` from an external file instead of editing source (ties into #4
  above).

## 6. Add Proxmark3 (pm3) as a supported reader
Deferred until after the command-line tools have all been exercised and verified
over PC/SC and libnfc - do that pass first, then come back to this.

Approach: **drive the Iceman/RRG pm3 client** (not the native wire protocol). The
Iceman fork ships a `pm3` Python module - `p = pm3.pm3(); p.console("hf 14a apdu -s
<hex>"); p.grabbed_output` - so we issue client commands and parse the text output.
`hf 14a apdu` is exactly the ISO-7816 transceive the APDU tools (EMV/ePassport/JCOP)
need, so that path lights up first; add MIFARE (`hf mf`) and LF (`lf ...`) after.

Integration surface (mirrors the libnfc branches):
- new `READER_PM3` constant in `RFIDIOt.py`; a `READER_PM3` branch in the ~10 methods
  libnfc touches: `__init__`, `info`, `reset`, `select`, `hsselect`, `send_apdu`,
  `login`, `readblock`, `readMIFAREblock`, `shutdown`.
- new `rfidiot/pypm3.py` support module (the pm3-client analog of `pynfc.py`):
  open/close the client, select 14443A (UID/ATQA/SAK), APDU transceive, later MIFARE.
- option wiring in `rfidiot/__init__.py` (a `-R READER_PM3` / device option, mirroring
  the `-f` libnfc handler).

Caveats: client console output is version-sensitive (pin to one Iceman release and
parse defensively); higher latency than a native transceive; needs the Iceman client
built with Python support on the host. Minimum viable = 14443A select + APDU, which
is enough for ChAP/mrpkey/rfidiot-cli over the pm3.

## 7. Work through the open GitHub issues until they're all closed
Ongoing housekeeping: on a regular basis, pick up
<https://github.com/AdamLaurie/RFIDIOt/issues> and clear issues until the list is
empty. For each: reproduce or verify against `master`, then fix-and-close,
close-as-resolved/obsolete (with a comment explaining why and inviting a reopen),
or close-as-wontfix. Use `gh issue list/view/comment/close`.

Closed in the 2026-10-07 session: #11 (Corrected-MRZ check digits, fixed), #12
(pynfc timeout - `-t 0` = infinite), #13 (libnfc 1.7.0, obsolete -> 1.8), #21
(`.ser` AttributeError, silent-init path removed), #25 (`smartcard` NameError,
guarded import), #40 (Py3 switch, done).

Closed in the 2026-10-08 session: #49 (ACR122 emulate IndexError in
`acs_transmit_apdu` - guard short/empty SCardControl response -> clean SW 6300),
#23 (ACR122U "Failed to control" with no card - a libccid CCID-escape config
requirement; made the hint Linux-aware), #35 (import-time exit - `rfidiot.card`
is now lazy via PEP 562, so `import rfidiot` has no hardware side effect), #46
(cannot-reproduce; pcscd saw 0 readers = host driver/daemon issue, not RFIDIOt),
#16 (usage: a libnfc PN533 reader needs `-R READER_LIBNFC`/`-f`, not PC/SC).

Remaining are mostly hardware-specific (ACR122 reader support #30, serial
readers, specific tags: NTAG213 #24, iClass #28), writeblock gaps (#20/#26 - libnfc
writeblock not implemented), and meta/feature requests (PyPI #22, examples dir #8,
license #14, Windows #39, nfckey #47, acg.de gone #18). Tackle the hardware ones
when the matching reader/card is to hand; the writeblock gaps tie into section 3;
the meta ones can be done anytime.

## 8. DemoTag deprecation follow-up
`demotag.py` is now marked **DEPRECATED** (v3.0a): the IAIK TUG DemoTag is
long-obsolete research hardware and `READER_DEMOTAG` is only vestigially wired in
- it is defined as a constant (`RFIDIOt.py:244`) but has no `reset`/`version`/
`info`/`select`/`send_apdu` branch, so the reader type is effectively a no-op. Open
question: fully remove the `READER_DEMOTAG` path (the constant, the `-R` wiring, the
`DT_SET_UID`/`DT_ERROR` command set and `demotag()` method, and the tool itself)
rather than carrying dead code, vs. keeping it for historical reference. Decide
before the next housekeeping pass; if removing, it is a clean self-contained delete.

## 9. Consider an Android emulator back-end for pn532emulate / pn532mitm
Today the EMULATOR (target) role in `pn532emulate.py` and `pn532mitm.py` is a PN532
driven via `TgInitAsTarget`. Investigate using an Android phone (Host Card Emulation)
as the emulator instead - there is already precedent for Android integration
(`READER_ANDROID` / `rfidiot/pyandroid.py`, an Android NFC device over a socket), so
the socket-relay form of `pn532mitm` could terminate at an HCE app on the phone.

Why it's worth it: cheap, ubiquitous hardware (no PN532/ACR122 needed for the target
side); and it may sidestep the PN532's forced `08` UID first byte (the chip only
takes a 3-byte NFCID1t and hard-wires byte 0 to `08` - see the note in
`pn532emulate.py`/`pn532mitm.py`). Exact for ePassports, but a hard limit otherwise.

Caveats to check first: Android HCE emulates an ISO/IEC 14443-4 Type A PICC at the
**APDU** level only (SELECT-AID routed to a service) - the app does not drive
low-level anticollision, and the UID is still OS-controlled (typically a random UID
that also begins with `08`), so HCE may not actually buy arbitrary-UID emulation
either. It also cannot emulate raw MIFARE Classic. So the realistic win is a
convenient APDU-level target for the eMRTD/EMV MITM path, not full low-level control;
confirm what a current Android release exposes before committing. Minimum viable: an
HCE app speaking the existing `pn532mitm` socket protocol as the EMULATOR end.

## 10. Chameleon Ultra helper app (reader + emulator back-end over serial)
Add support for the Proxgrind/RRG **Chameleon Ultra** (and Lite) as both a reader
and an emulator. Unlike the PN532 it drives its own anti-collision, so it can emulate
an **arbitrary 4- or 7-byte UID** (no forced `08` first byte - see the note in
`pn532emulate.py`/`pn532mitm.py`), which also makes it a strong emulator candidate for
the MITM/clone use in sections 8-9.

Protocol (from RfidResearchGroup/ChameleonUltra `software/script/chameleon_com.py` +
`firmware/application/src/data_cmd.h`): USB CDC-ACM serial at 115200. Binary frame,
all multi-byte fields big-endian:

    SOF(1)=0x11 | LRC1(1) of SOF (always 0xEF) | CMD(2) | STATUS(2) | LEN(2) |
    LRC2(1) over SOF..LEN | DATA(LEN) | LRC3(1) over SOF..DATA

where each LRC = `(0x100 - (sum(preceding bytes) & 0xFF)) & 0xFF`. A response reuses
the same frame (CMD echoed, STATUS = result code, DATA = payload). Auto-detect the
port by the device's USB VID/PID, as the official client does.

Key command IDs (decimal):
- device/mode: GET_APP_VERSION 1000, GET_DEVICE_CHIP_ID 1011, GET_DEVICE_MODE 1002,
  CHANGE_DEVICE_MODE 1001 (reader vs. tag/emulator).
- reader HF: HF14A_SCAN 2000 (UID/ATQA/SAK), HF14A_RAW 2010 (arbitrary APDU
  transceive - the ISO-7816 path ChAP/mrpkey/rfidiot-cli need), MF1_AUTH 2007 /
  MF1_READ 2008 / MF1_WRITE 2009. reader LF: EM410X_SCAN 3000.
- emulation/slots: SET_ACTIVE_SLOT 1003, SET_SLOT_TAG_TYPE 1004, SET_SLOT_ENABLE 1006,
  SLOT_DATA_CONFIG_SAVE 1009; HF14A_SET_ANTI_COLL_DATA 4001 (set emulated UID/ATQA/SAK
  - the arbitrary-UID win), MF1_WRITE_EMU_BLOCK_DATA 4000 (load a MIFARE dump block by
  block), EM410X_SET_EMU_ID 5000.

Integration surface (mirrors the libnfc / planned pm3 branches in section 6):
- `rfidiot/pychameleon.py` support module (analog of `pynfc.py`): pyserial open/close
  + port auto-detect, the frame codec above, `send(cmd, data) -> (status, resp)`, and
  typed helpers for the commands listed. Defensive parsing (validate each LRC) and a
  firmware-version pin, since command IDs can shift across releases.
- new `READER_CHAMELEON` constant in `RFIDIOt.py`; a branch in the ~10 reader methods
  (`__init__`, `info`, `reset`, `select`, `hsselect`, `send_apdu`, `login`,
  `readblock`, `readMIFAREblock`, `shutdown`), using CHANGE_DEVICE_MODE->reader +
  HF14A_SCAN for select and HF14A_RAW for APDU transceive.
- option wiring in `rfidiot/__init__.py`: `-R READER_CHAMELEON` with the serial port
  via `-l` (or auto-detect), mirroring the `-f` libnfc handler.
- new root tool, e.g. `chameleon.py`, for the emulator/loader side:
  - `SLOT <n> UID <hex> [ATQA <hex> SAK <hex>]` -> active slot + 14A type +
    HF14A_SET_ANTI_COLL_DATA + save (arbitrary UID, incl. 7-byte).
  - `SLOT <n> MFLOAD <dump.bin|.mct>` -> MF1_WRITE_EMU_BLOCK_DATA per block + anti-coll
    from block 0 + save (clone a dumped MIFARE Classic 1K/4K into a slot).
  - `SLOT <n> EM410X <id>` -> EM410X_SET_EMU_ID + save.
  This also lets `rfidiot-cli.py DUMP` (read a card via the reader back-end) feed
  straight into a Chameleon slot - i.e. "clone to Chameleon".

Caveat for the MITM (section 9 context): the Chameleon's HF emulation is **slot/data
based** (it answers from stored anti-coll + MIFARE block data), not a live
ISO-14443-4 APDU relay like the PN532's `TgInitAsTarget`. So it is ideal for cloning a
dumped card or a chosen UID, but is **not** a drop-in live-relay emulator for
`pn532mitm` unless the firmware exposes an APDU-forwarding emulation mode - check
before assuming the MITM target role. Minimum viable here: the reader back-end
(HF14A_SCAN + HF14A_RAW) so ChAP/mrpkey/rfidiot-cli work over a Chameleon, plus the
`chameleon.py` UID/dump loader.
