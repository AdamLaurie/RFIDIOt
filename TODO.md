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
(Update: at the UID layer this is now beaten on libnfc PN53x by `emulateuid.py` - see section 14.)

Caveats to check first: Android HCE emulates an ISO/IEC 14443-4 Type A PICC at the
**APDU** level only (SELECT-AID routed to a service) - the app does not drive
low-level anticollision, and the UID is still OS-controlled (typically a random UID
that also begins with `08`), so HCE may not actually buy arbitrary-UID emulation
either. It also cannot emulate raw MIFARE Classic. So the realistic win is a
convenient APDU-level target for the eMRTD/EMV MITM path, not full low-level control;
confirm what a current Android release exposes before committing. Minimum viable: an
HCE app speaking the existing `pn532mitm` socket protocol as the EMULATOR end.

## 10. Chameleon Ultra helper app (reader + emulator back-end over serial)
**[DONE] Reader back-end** (`READER_CHAMELEON`, commit adds `rfidiot/pychameleon.py`):
the Chameleon Ultra works as an ISO 14443-A reader over USB CDC serial - frame codec,
USB auto-detect, firmware-version gate, `HF14A_SCAN_KEEP` select, and a T=CL APDU
engine (I-block toggling, S(WTX), receive chaining) over `HF14A_RAW`. Hardware-verified
on hw_v1 / fw v2.2.0: a full `mrpkey.py -R READER_CHAMELEON` ePassport read (BAC +
secure messaging + EF.COM/SOD/DG1/DG2/DG14, incl. the 18 KB DG2 JPEG via chaining;
Passive Auth confirms the DG hashes).

**[DONE] MIFARE Classic reader ops** (`MF1_AUTH/READ/WRITE` 2007/2008/2009 in
`pychameleon.py`; `READER_CHAMELEON` branches in `login`/`readblock`/`writeblock`,
library `VERSION` 3.1c). The firmware auths on every MF1 command, so `login()` runs
`MF1_AUTH` to verify + stash the key and the subsequent `readMIFAREblock`/`writeblock`
re-auth with it. New `CU0x` error strings (`ChameleonErrorCodes`) + the "gemeral"->
"general" punt fix. Hardware-verified on a MIFARE Classic 1K (SAK 08, transport Key A
`FFFFFFFFFFFF`): `readmifare1k.py` (full dump + access-bit decode), `loginall.py`,
`readmifaresimple.py`, `bruteforce.py` all read; `writemifare1k.py` writes data blocks
(sector trailers correctly skipped, verified by read-back); `rfidiot-cli.py` MF
KEY/AUTH/DUMP/READ/WRITE/WIPE/CLONE all work (WIPE rewrites trailers/keys; CLONE
source->blank copy verified by read-back); wrong key / non-Classic fails cleanly
with `CU01`. (Also fixed a Py3 bug surfaced in
`rfidiot-cli.py` MF WRITE: `len(data) / 16` -> `// 16`, which made `end` a float and
broke the `{end:02X}` format.)

**[DONE] MIFARE Ultralight (Type 2) read** over the Chameleon (library `VERSION`
3.1d). `pychameleon.ul_read()` does a no-auth 14443-3 READ (`0x30`) via `HF14A_RAW`
(CRC on, no RATS) returning 16 bytes; the `READER_CHAMELEON` `readblock` branch routes
to it when no MIFARE key is stashed (Classic logs in first; UL/NTAG never does), the
analogue of `libnfc_mifare_read_block`. Also guarded `readmifareultra.py`: a header-
block read failure now exits cleanly instead of crashing on an undefined `lock0`
(`NameError`, a pre-existing bug on ANY reader when the read fails). Hardware-verified
on a MIFARE Ultralight (UID `047BFDB22D6181`): `readmifareultra.py -R READER_CHAMELEON`
reads the pages + lock/OTP decode.

**[STARTED] Emulator / slot tooling** (`chameleon.py`, library `VERSION` 3.1e).
pychameleon gained the slot/emulation commands (SET_ACTIVE_SLOT 1003, SET_SLOT_TAG_TYPE
1004, SET_SLOT_DATA_DEFAULT 1005, SET_SLOT_ENABLE 1006, SLOT_DATA_CONFIG_SAVE 1009,
GET_ACTIVE_SLOT 1018, GET_SLOT_INFO 1019, HF14A_SET_ANTI_COLL_DATA 4001,
MF1_WRITE_EMU_BLOCK_DATA 4000, EM410X_SET_EMU_ID 5000) plus the TagSpecificType /
TagSenseType constants, plus `reboot()` (ENTER_BOOTLOADER 1010 - the only reset the
firmware offers; there is no power-off command). New `chameleon.py` tool: `INFO`
(list the 8 slots + active), `SLOT <n> UID <hex> [TYPE/ATQA/SAK/ATS]` (emulate an
arbitrary 4/7/10-byte UID - the win over the PN532's forced `08`), `SLOT <n> MFLOAD
<dump>` (load a raw MIFARE dump via MF1_WRITE_EMU_BLOCK_DATA + anti-coll from block 0),
and `REBOOT`. Hardware-verified end-to-end: `SLOT 8 UID 11223344` was read back over
the air by an independent reader (ACR122U `-f ccid`): `Tag ID 11223344 ATQA 0004
SAK 08 MIFARE Classic 1K`. A full-card clone (`MFLOAD` of a 64-block dump) emulated and
read back sector-for-sector too; over-the-air read-back of the emulated tag is
coupling-sensitive (varies run to run - a stable antenna mount helps).

To enable writing/cloning cards, two general (non-Chameleon) additions landed in the
same `VERSION` 3.1e change:
- **libnfc/ACR122CCID MIFARE Classic write**: `libnfc_mifare_write_block()` +
  `writeblock()` libnfc branch (none existed before). The PN532 InDataExchange reports
  a bogus 0x02 status on a MIFARE write even when it lands, so the write verifies by
  reading the block back (re-auth with the key stashed by `libnfc_mifare_login`).
- **dump trailer-key patching**: `mifare_is_trailer()` + `mifare_patch_trailer()`
  helpers, used by `rfidiot-cli MF READ`, patch the authenticating key back into a
  dumped sector trailer (a card never returns Key A - it reads as 000000 - so an
  un-patched dump can't be cloned/written back). `rfidiot-cli CLONE` and
  `readmifaresimple COPY` already reconstruct trailers on write.

**Remaining:**
- `chameleon.py`: `SLOT <n> EM410X <id>` (LF slot + EM410X_SET_EMU_ID; the pychameleon
  method exists, just the tool sub-command).
- LF EM410x reader (`EM410X_SCAN` 3000) if wanted.
- **MIFARE Ultralight / Type 2 WRITE, across the board.** Read is done (above) but
  there is no UL *write* on any back-end: `writeblock()` on PCSC/ACS/libnfc/Chameleon
  all target MIFARE Classic (16-byte block, and on the Chameleon an `MF1_WRITE` that
  needs a stashed key -> `CU04` for a keyless UL). Add a no-auth 14443-3 WRITE
  (`0xA2`, **4 bytes to one page**) path and route `writeblock()` to it for Type 2 the
  same way reads now route (no stashed key / SAK `00`):
  - `pychameleon.ul_write(page, data4)` via `HF14A_RAW` - note UL WRITE answers a 4-bit
    **ACK** (`0x0A`), not a CRC'd frame, so the response framing differs from `ul_read`
    (no `CHECK_CRC` on the reply) - verify on hardware.
  - libnfc has `MC_WRITE` (`0xA0`, 16-byte compatibility write) already; add the UL
    `0xA2` 4-byte write too for NTAG/UL that reject `0xA0`.
  - a client tool (`writemifareultra.py`, mirroring `readmifareultra.py`) and make
    `rfidiot-cli.py WRITEHEX` accept a 4-byte UL page.
  - DESTRUCTIVE + page 3 is one-way OTP and pages 0-2 are UID/lock: tools must refuse
    or loudly warn on pages <= 3; test only on a user data page with read-back/restore.

Add support for the Proxgrind/RRG **Chameleon Ultra** (and Lite) as both a reader
and an emulator. Unlike the PN532 it drives its own anti-collision, so it can emulate
an **arbitrary 4- or 7-byte UID** (no forced `08` first byte - see the note in
`pn532emulate.py`/`pn532mitm.py`), which also makes it a strong emulator candidate for
the MITM/clone use in sections 8-9.

**Prerequisite: current firmware (>= v2.2.0, the modern command set).** The reader
path depends on `HF14A_RAW` (2010); it and other modern commands (`HF14A_SCAN_KEEP`
2016, `GET_GIT_VERSION`, `GET_SLOT_INFO`, `GET_DEVICE_MODEL`) are absent on old
firmware and return status `0x67 INVALID_CMD` (verified against a unit on an ancient
build: `GET_APP_VERSION` reported `00 01`, `HF14A_SCAN` worked but had no ATS field,
and `HF14A_RAW` was unimplemented). So the back-end must, on open, read
`GET_APP_VERSION`/probe `HF14A_RAW` and refuse with a clear "update the Chameleon
firmware (RfidResearchGroup/ChameleonUltra latest release, ultra-dfu-app.zip)" message
rather than failing obscurely. Document the firmware floor in README/CLAUDE.md too.

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

## 11. ACR122U long-response reads over libnfc - **[DONE]**
The ACR122U's PN532 reassembles ISO 14443-4 (T=CL) chained responses in a small
internal buffer and overflows on long records, aborting the transceive with
pseudo-status `63 27` ("RF Transmission Error" at the libnfc layer). Any 14443-4
response that chains was unreadable on this reader: an EMV issuer-public-key-
certificate record (248 bytes) and an ePassport DG2 (18 KB) both failed, so `ChAP.py`
offline auth (`-c`) and `mrpkey.py` DG reads broke over an ACR122U while working on a
PN53x. Records that fit one frame succeeded, which made it look intermittent.

Fix (commits `ee7eb03`/`e205f85`/`3406f17`, library `VERSION` 3.0g, `ChAP.py` Ver
3.1b): when the opened libnfc device is an ACR122U (detected by its `acr122`
connstring prefix - the reader name is a generic "CCID USB Reader") and a 14443-4
card is selected (SAK bit `0x20`), turn libnfc "easy framing" **off** right after
RATS and drive T=CL in software in `pynfc` - I-block number toggling, R(ACK) for
receive-side chaining, S(WTX) echoes - the same engine as the Chameleon back-end
(section 10). Two parts were needed:
- `enable_software_tcl()` (in `select()`, which `hsselect()` delegates to): each raw
  I-block now stays within one frame, so the PN532 never overflows.
- raise `NP_TIMEOUT_COM` to 3000 ms while software T=CL is active. libnfc's default
  raw-transceive (InCommunicateThru) timeout is ~52 ms; with easy framing on libnfc
  extends it itself for ISO 14443-4, but with it off we own T=CL, so a card's S(WTX)
  waiting-time-extension request (e.g. ePassport BAC's `EXTERNAL AUTHENTICATE`, which
  runs 3DES on-chip) would otherwise RF-error at ~52 ms. EMV didn't surface this (its
  reads return quickly); mrpkey's BAC did.

Scoped to the ACR122U only - other libnfc readers (the SCL3711/PN53x, which chain in
firmware) are byte-for-byte unchanged; `sendAPDU`'s raw transceive was factored into
`_raw_frame()` and shared by both paths.

Hardware-verified on an ACR122U/Touchatag (libnfc `acr122_usb`):
- `ChAP.py -f 0 -c`: full contactless EMV read, 0 driver/read errors, SDA/DDA cert
  chain recovered and verified (CA 1984-bit -> Issuer 1408-bit -> ICC 1024-bit,
  including the 248-byte chained issuer cert).
- `mrpkey.py -f 0 <MRZ>`: full ePassport BAC + secure messaging, EF.COM/SOD/DG1/DG2/
  DG14, the 18,417-byte EF.DG2 JPEG read in full via T=CL chaining.

Second unit tested (ACR122U-WB-R) - the libnfc path can't even open it, so a new
direct-CCID back-end was added. Only the Touchatag/tikitag ACR122 (PID `072f:90cc`
with older firmware) was on hand for the original fix; a retail **ACR122U-WB-R** was
tried next and exposed a deeper, unrelated problem: this unit enumerates with the
**ACR38 PID `072f:90cc`** (iProduct "CCID USB Reader", firmware string "ACR122U..."),
and *every* off-the-shelf driver misidentifies it:
- **libnfc 1.8.0 `acr122_usb`** fails its PN532 power-on init ("Unable to open NFC
  device") - libnfc 1.8.0 (2018) predates this firmware. Ruled out, each by test:
  pcscd contention, USB permissions (node is `rw` via ACL+plugdev), dead hardware
  (the PN532 answers raw CCID instantly and returns its "ACR122U" firmware string),
  an init timeout (0 ms response), and a stale bulk-IN frame (drained clean).
- **libccid/PC-SC** loads its **ACR38 contact driver** (`ACS ACR 38U-CCID`) and
  negotiates the contactless card as **T=0**. A single simple SELECT (`IDENTIFY`)
  works, but a real T=CL EMV APDU sequence fails (`Failed to transmit with protocol
  T0`, `0x80100016`) and wedges the reader off the USB bus (needs a replug).

The PN532 behind it is fine - it answers raw CCID pseudo-APDUs perfectly. So the fix
was a new **direct-CCID ACR122U back-end** in `rfidiot/pynfc.py` (`ACR122CCID`): it
talks straight to the reader's CCID bulk endpoints over `usbdevfs` (no libnfc, no
pcscd), wraps PN532 commands in ACR122U direct-transmit pseudo-APDUs (`FF 00 00 00 Lc
..`, following T=0 `61xx` GET RESPONSE), selects via `InListPassiveTarget`, and drives
each ISO 14443-4 I-block via `InCommunicateThru` through the **same** software T=CL
engine as the libnfc path (the T=CL loop was factored into `_tcl_exchange()` and a
`_ISODEP` mixin, shared by both `NFC` and `ACR122CCID`). CRC is left to the PN532
(CIU TxCRCEn/RxCRCEn, matching libnfc's HANDLE_CRC). Select it with `-f ccid` (first
ACS reader) or `-f ccid:<bus>:<dev>`; `RFIDIOt.select()` auto-enables software T=CL
for 14443-4 just as on the libnfc path (`is_acr122` is set).

Hardware-verified on the ACR122U-WB-R (`-f ccid`):
- `ChAP.py -f ccid -c`: full contactless EMV read - both AIDs (Debit Mastercard +
  companion A000000029), the whole transaction log, and the chained **248-byte Issuer
  Public Key Certificate** - offline cert chain verified end to end (CA 1984-bit ->
  Issuer 1408-bit -> ICC 1024-bit, PAN match), zero read/driver errors, no `63 27`.
- `mrpkey.py -f ccid <MRZ>`: full ePassport BAC + secure messaging, EF.COM/SOD/DG1/
  DG2/DG14, the 18,417-byte EF.DG2 JPEG read via T=CL chaining, Passive Authentication
  DG1/DG2/DG14 hashes OK.

Two bugs found and fixed during bring-up:
- the T=0 `61xx` GET RESPONSE must use the ACR122U pseudo-APDU class **`FF C0`**, not
  T=0's `00 C0` (the latter returns CCID `bStatus` "command failed", so every PN532
  reply came back empty - nothing selected);
- the PN532 InCommunicateThru RF timeout defaults to ~52 ms, so a card's **S(WTX)**
  (ePassport BAC EXTERNAL AUTHENTICATE runs 3DES on-chip) RF-errored after we echoed
  the WTX. Fixed by raising RFConfiguration item 0x02 fRetryTimeout to 0x10 (~3.3 s)
  in `enable_software_tcl()` - the direct-CCID analogue of the libnfc NP_TIMEOUT_COM
  bump (section 11, WTX). EMV didn't surface it (its reads return fast); BAC did,
  exactly as on the libnfc path.

**[DONE] ISO 14443-B on the direct-CCID back-end** (library `VERSION` 3.1f).
`ACR122CCID.selectISO14443B()` polls with InListPassiveTarget 106B (the PN532 sends
REQB + ATTRIB itself) and `RFIDIOt.select()` takes over T=CL in software for
14443-4 Type B cards, as for Type A. Two things were needed:
- **CID-aware T=CL.** The PN532's ATTRIB assigns CID 1 (= Tg), and a card given a
  non-zero CID ignores blocks without it (verified: SELECT without CID = no answer,
  with CID = `9000`). `_tcl_exchange()` now takes an optional `cid`: every I/R/S block
  carries PCB bit `0x08` + the CID byte, and the card's echoed CID is stripped. With
  no CID the frames are byte-for-byte unchanged. The CID is only used when the ATQB
  says the card supports it (FO bit 0).
- **Stale-reply fix in the CCID transport.** `_xfrblock()` accepted any bulk-IN
  message, so one late reply (e.g. a poll the reader gave up on with `63 0x`, or one
  left from a previous process) shifted every later exchange by one, and the
  `61xx` GET RESPONSE length was then applied to the wrong command (truncated
  replies). It now drops messages whose type/`bSeq` don't match the command sent.
  Affects Type A on this back-end too (strictly a fix).
Hardware-verified on an ACR122U-WB-R (`-f ccid`) with a Type B (random-PUPI) GBR
ePassport: `mrpkey.py -f ccid <MRZ>` full BAC + SM read, EF.COM/SOD/DG1/DG2/DG14,
18 KB DG2 via chaining, PA hashes DG1/DG2/DG14 OK. Not done on the libnfc path
(libnfc doesn't expose the ATTRIB-assigned CID; untested there).

Remaining on the direct-CCID back-end:
- Jewel and iClass `select*` return None.
- **[DONE] MIFARE Classic on the direct-CCID back-end** (library `VERSION` 3.1h),
  hardware-verified on a MIFARE Classic 1K: `readmifare1k.py` (full card),
  `loginall.py`, `rfidiot-cli` MF KEY/AUTH/DUMP/READ (1 KB dump, trailer key patched)
  and single-block writes via WRITEHEX and MF WRITE (block 05 written, read back,
  restored; a wrong-key write fails cleanly in 0.6 s). Fixed on the way: a wrong-key
  auth crashed the tools with a USB `TimeoutError`. The PN532 keeps RF settings
  across processes, and `enable_software_tcl()` raises fRetryTimeout to ~3.3 s, so a
  later MIFARE auth with a wrong key (the card just stays silent) waited longer than
  the 3 s USB read. Now `_pn532_init()` and `configMifare()` restore the PN532
  default RF timeouts, and `_xfrblock()` reports a USB timeout as a failed exchange
  (the late reply is dropped by the bSeq check).
- **[DONE]** (library `VERSION` 3.1h) **Sector trailers in dumps and trailer
  writes.** `login()` records the key type + key that actually authenticated (cleared
  on failure; reader branches moved unchanged into `_login()`), and
  `readMIFAREblock()` patches every sector trailer it reads with that key, so every
  dump on every back-end is clonable (`rfidiot-cli` MF DUMP/READ, `readmifare1k`,
  `readmifaresimple`, ...). And `libnfc_mifare_write_block()`'s read-back check no
  longer fails every trailer write (Key A always reads back as zeros, so CLONE/WIPE/
  MF WRITE of a full dump stopped at the first trailer): for a trailer it patches in
  the auth key, accepts an all-zero (hidden) key field, and so verifies the access
  bits + user byte and any key the card shows. Hardware-verified on `-f ccid`:
  trailers show the real Key A; block 07 rewritten with its own bytes reports OK
  (was "Failed"), sector intact. The mismatch cases (access bits / visible Key B /
  data block) are unit-tested offline, not on hardware.
- **[DONE]** `writemifare1k.py` (v3.0c) called `card.login(sector, ...)` with the
  **sector** number, but `login()` takes a **block** number on PC/SC/ACS/libnfc/CCID/
  Chameleon (only the ACG serial branch sends it as a sector; `readmifare1k` already
  passes `sector * 4`). So for sector N it authenticated block N (another sector) and
  the write to block 4N was refused; 4N+1/4N+2 then landed only because the libnfc
  write's read-back re-authenticates the right sector. Hardware-confirmed on `-f ccid`
  (45 of 135 writes failed - exactly blocks 4N), fixed to `sector * 4`: all 135 writes
  OK, card contents match, trailers untouched; card restored from a backup dump
  afterwards. (The tool still writes each sector once per key type A/B/FF - harmless.)
- **[DONE]** (library `VERSION` 3.1g) Type B fallback in the tools: `rfidiot-cli.py`
  IDENTIFY/SELECT/HSS (v3.1d), `cardselect.py` (v3.1c) and `ChAP.py` (3.1c) now try
  `select("B")` when no Type A card answers (only libnfc/CCID distinguish A from B;
  other readers ignore `cardtype`, the Chameleon refuses B at once). IDENTIFY and
  cardselect print PUPI / Application Data / Protocol Info for a Type B card. A Type B
  select now clears the stale Type A ATQA/SAK. Also fixed on this back-end: a second
  select in a row failed (A or B) because the card was still activated and ignored
  REQA/REQB - `selectISO14443A/B()` now cycle the RF field first, as the libnfc path
  does. Hardware-verified on `-f ccid`: `IDENTIFY SELECT HSS 4 IDENTIFY` all succeed on
  both a Type B ePassport and a Type A Debit Mastercard; `ChAP.py -c` and the full
  `mrpkey.py` read unchanged. Not changed (no Type B use): the MIFARE/LF/Hitag tools,
  `readtag.py` (block reads), `send_apdu.py` (PC/SC only), `nfcid.py` (Android), the
  JCOP tools (Type A cards); `isotype.py`/`multiselect.py` already tried B.
- Consider auto-falling back to the direct-CCID back-end when libnfc fails to open an
  `acr122` device, instead of requiring the explicit `-f ccid`.
- A lighter alternative worth noting: an `/etc/libccid_Info.plist` override mapping
  `072f:90cc` to the ACR122U PICC behaviour might fix the PC/SC path too (untried).

- **Bare libnfc connstring (`-f pn53x_usb`) opens the wrong device.** Passed as-is
  to `nfc_open()`, libnfc 1.8's `pn53x_usb` driver (from memory of its source, not
  checked here) doesn't filter by VID/PID when no bus:dev is given: it opens the first
  USB device it can, resets it, tries to set its configuration and gives up on
  failure. Seen 2026-10-12: `-f pn53x_usb` failed with "Unable to set USB
  configuration (EPERM) ... device 1d6b:0003" (the root hub) while
  `-f pn53x_usb:003:009` opened the SCL3711. Risk: on a host where the first
  openable device is writable, the bare form would reset an unrelated device. Fix
  (not done): in `pynfc.NFC.configure()`, resolve a bare driver name via sysfs to the
  first matching VID:PID and rewrite it to `<driver>:BBB:DDD` (like
  `ACR122CCID._find()`); raise a clear error if none. Tables: `pn53x_usb` 04cc:0531,
  054c:0193, 04cc:2533, 04e6:5591 (SCL3711), 04e6:5594, 054c:02e1, 1fd3:0608;
  `acr122_usb` 072f:2200, 072f:90cc, 072f:2214. Then fix `docs/readers.md`, which says
  the bare form opens the first match.

Other ACR122-family variants (ACR122T, ACR1222L, clones/relabels) may differ again;
the software-T=CL fix should still apply on any that libnfc *can* open (it detects by
the `acr122` connstring prefix), and the direct-CCID back-end covers ACS units that
libnfc/pcscd cannot. May relate to the open "ACR122 reader support" issue #30.

Affected tools (the 14443-4 APDU path over an ACR122U via libnfc): `ChAP.py` and
`mrpkey.py` (both verified above); `rfidiot-cli.py` APDU/SELECT/IDENTIFY;
`jcopsetatrhist.py`/`jcopmifare.py` contactless JCOP; `nfcid.py` (enables the mode but
only reads the UID). NOT affected: any non-ACR122U libnfc reader; PC/SC-only tools
(`send_apdu.py` uses `pcsc_send_apdu` directly; `pn532mitm.py`/`pn532emulate.py` use
the ACS path); serial readers; all MIFARE Classic/Ultralight tools (SAK lacks `0x20`
and/or go via `configMifare`, which forces software T=CL off); LF tools.

Known limitation: software T=CL sends each command as a single I-block (no SEND-side
chaining), matching the Chameleon back-end. A command APDU whose data field exceeds
one frame (extended-length / >~255-byte command) over an ACR122U+14443-4 wouldn't be
chained. The read flows (passport, EMV, IDENTIFY, JCOP select/auth) never do this; the
only realistic trigger is loading a large data/applet block to a JavaCard via
`jcopmifare`/`jcoptool` - and GP load blocks are <=255 bytes and normally done over
contact PC/SC. If ever needed, send-side chaining is a small addition. May relate to
the open "ACR122 reader support" issue #30 (section 7) - check it against this.

Existing tools the reader back-end would unlock (exposes 14443-A select + ISO-7816
APDU transceive + MIFARE Classic auth/read/write, and LF EM410x read; NO 14443-B,
15693 or Hitag):
- Works well: `rfidiot-cli.py` (best fit - IDENTIFY/APDU/DUMP/SELECT/MF *), `mrpkey.py`
  (ePassport APDU), `ChAP.py` (contactless EMV APDU), `send_apdu.py`, `nfcid.py`; the
  MIFARE Classic tools `readmifare1k.py`/`writemifare1k.py`/`readmifaresimple.py`/
  `formatmifare1kvalue.py`/`loginall.py`/`bruteforce.py`/`copytag.py`/`unique.py`;
  `readmifareultra.py` (Ultralight via raw 14A); and the select/identify tools
  `cardselect.py`/`multiselect.py`/`isotype.py`/`readtag.py`.
- Works but caveated: `ChAP.py`/`mrpkey.py`/`isotype.py` only for **Type A** cards
  (EMV and ICAO also allow Type B, which the Chameleon can't read - keep PC/SC or
  libnfc for those); `jcoptool.py`/`jcopmifare.py`/`jcopsetatrhist.py` only for
  **contactless** JCOP (their usual contact T=0 path is out).
- Out of scope: the 125 kHz / Hitag tools `hitag2brute.py`/`hitag2reset.py`/
  `hidprox.py`/`fdxbnum.py`/`q5reset.py`/`lfxtype.py`/`readlfx.py`/`writelfx.py`
  (Chameleon LF *reader* only does EM410x scan + T55xx write, not HID/Hitag/FDX-B/EM4x
  reads); and `froschtest.py`/`demotag.py` (those are specific serial readers).

## 12. libnfc card-emulation (EMULATOR role) for pn532emulate / pn532mitm - **[DONE]**
The EMULATOR (target) role in `pn532emulate.py` and `pn532mitm.py` used to require an
ACS PN532 (the `TgInitAsTarget` ACS pseudo-APDU path). A libnfc ACR122U/tikitag (`-f`)
can now take that role too, **as well as** the ACS path - not instead of it. Section 9
(Android HCE) remains a future third back-end for the same role.

Fix (commits `7e0f769` pn532emulate, `e771bcf` pn532mitm; library `VERSION` 3.1b).
New pynfc target-mode helpers on the `NFC` class: `make_iso14443a_target()` builds an
ISO 14443-A `NFC_TARGET` (ATQA/UID/SAK/ATS), `initAsTarget()` enters target mode and
blocks for activation, `targetReceive()`/`targetSend()` exchange frames. Critical
ordering: libnfc "easy framing" must be set **after** `nfc_target_init` (it resets the
device properties), else target send/receive returns `NFC_ENOTIMPL` (libnfc only
implements the easy-framing receive path for DEP). Also fixed `nfc_perror`'s argtype
(`c_char_p`, was `c_wchar_p`) so it prints the whole label.

`pn532emulate.py` dispatches by the SAK bit `0x20` of the requested card:
- **Type 4** (ISO 14443-4 / T=CL / APDU): easy framing **on**, the chip drives T=CL and
  we answer bare APDUs - the `nfc-emulate-forum-tag4` approach. Needs a PN532
  (ACR122U/tikitag) that answers RATS in hardware.
- **Type 2** (ISO 14443-3 / Mifare UL memory): raw framing, a 16-page image (page 0 =
  UID, page 3 = CC `E1100600`, page 4 = `0300FE00`), serving `READ`(0x30) and `HALT`.

`pn532mitm.py` adds a libnfc EMULATOR side over the socket relay (`-f <n>
reader:HOST:PORT`): it presents an ISO 14443-4 target and synthesises the **same ACS
wire framing** the ACS emulator would (`D503..` firmware, `D58D..` activation,
`D587..` TgGetData, `targetSend(data+errorcode)` for TgSetData), so the READER side
stays the unchanged PC/SC code - on the same host (two shells) or another machine.

Proven matrix (hardware-verified):
- Type 2 emulation works on **both** the SCL3711 (PN533) and the tikitag (read back as
  a MIFARE Ultralight).
- Type 4 emulation works on the **tikitag/ACR122U** (`<< 00A4000C023F0000  >> 9000`).
- Type 4 does **not** work on the SCL3711: the PN533 hands RATS up to software, which
  can't meet the RATS->ATS timing, so a Type 4 target is refused on it with a clear
  message. (The ACR122U/PN532 answers RATS in hardware.)
- `pn532mitm` relay end-to-end: tikitag as the libnfc EMULATOR + the existing PC/SC
  reader side, a full ePassport read (`mrpkey.py`) relayed cleanly.

Remaining / limits:
- The `pn532mitm` libnfc emulator is **Type 4 only** (the Type 2 memory path lives in
  `pn532emulate`, not the relay); and it uses a default/passed ATS - the real card's
  ATS is not yet relayed over the socket (fine for most readers, may matter for picky
  ones).
- libnfc can't drive a reader **and** an emulator on the same host (device contention),
  so the libnfc emulator is socket-only: two shells on one host (reader on PC/SC,
  emulator on libnfc) or split across two machines. The PN532's hard-wired `08` UID
  first byte (section 9) still applies.

## 13. ELATEC TWN4 reader back-end (`READER_TWN4`)
**[DONE] HF core** (library `VERSION` 3.1i, `rfidiot/pytwn4.py`). Drives a TWN4 running
ELATEC's Simple Protocol app (ASCII mode, CRC off) over USB CDC (auto-detected,
`09d8:0420`) or `-l` for a true-serial unit. Function numbers from ELATEC's
`twn4.sys.h`, frame formats from the Simple Protocol doc (DocRev25) and confirmed on
the hardware (TWN4 MultiTech 2, `TWN4/B1.50/NCF5.25/PRS1.04/AV`). Checked against API
Reference DocRev31: all functions used match. DocRev31 also lists the system parameter
`ISO14443_3_TDX_CRCCONTROL` (34), which makes the firmware add/strip the CRC on raw
frames (verified on the reader); the driver forces it to 0 with `SetParameters` on
open, so a reader left with it set still works. (Not checked: Simple Protocol DocRev26+.)
- select: `SearchTag` narrowed to the requested type with `SetTagTypes`, then the
  reader's tag types are restored at once (the TWN4 keeps them until reset, and tools
  often exit without `shutdown()`); ATQA (LSB first from the reader, reversed), SAK,
  ATQB / answer to ATTRIB (CID).
- APDUs: `ISO14443_4_TDX` returns at most 255 bytes and the TWN4's own RATS (sent only
  when asked for the ATS) announces FSD 256, so EMV certificate records failed. Now:
  RATS sent by RFIDIOt with FSDI 7 (FSD 128) for SAK-bit-0x20 Type A cards, and T=CL in
  software (`pynfc._tcl_exchange`) over raw `ISO14443_3_TDX` frames with host-side
  CRC_A/CRC_B (checked against ISO 14443-3 Annex B and the ELATEC doc's example).
- Tools: `ChAP.py` (3.1d), `rfidiot-cli.py` IDENTIFY (v3.1f), `cardselect.py` (v3.1d),
  `isotype.py` (v3.1c) treat `READER_TWN4` like libnfc.
- Hardware-verified: `ChAP.py -c` on a Debit Mastercard (all records incl. a 256-byte
  issuer-cert record, chain verified); `mrpkey.py` on a Type B ePassport with BAC and
  PACE-AES (full read, PA hashes OK, ~8 s); IDENTIFY/SELECT/HSS (repeated), APDU,
  `cardselect`, `isotype` on Type A and B.

Remaining:
- MIFARE Classic / Ultralight (`API_MIFARECLASSIC` 11, `API_MIFAREULTRALIGHT` 12) for
  the MIFARE tools; NTAG (32), DESFire (15).
- LF tags via `SearchTag` (EM4102, HID Prox, FDX-B, Indala, AWID, ...) for the LF
  tools; also ISO 15693 (13), iCLASS (17), LEGIC, FeliCa.
- Type B frame size: the TWN4 sends ATTRIB itself, with its own max frame size; an
  ePassport with 118-byte reads works, but a Type B card chaining frames > 255 bytes
  would fail (no way found to re-ATTRIB).
- True serial (UART) TWN4 untested (only USB CDC).
- `chameleon`-style `twn4.py` tool for reader config (beep/LEDs, tag types)? Optional.

## 14. Card emulation on the ACR122U over direct CCID (`-f ccid`) - **[DONE]**
The direct-CCID back-end now has target (card-emulation) mode: TgInitAsTarget,
TgGetData/TgSetData (the PN532 runs ISO 14443-4 itself) and TgGetInitiatorCommand/
TgResponseToInitiator (raw frames) - the same calls as the libnfc back-end, so
`pn532emulate` and `pn532mitm` run over `-f ccid`, the only route that works on the
ACR122U-WB-R. Verified with the WB-R emulating and the SCL3711 reading: a plain target
(`08AABBCC`, ATQA byte order as libnfc sends it), and `pn532emulate` Type 4 (the PN532
answers the RATS; the APDU arrives and gets 9000). A host answering ISO 14443-3
anticollision itself (to beat the hard-wired `08` first UID byte) gets REQA -> ATQA and
ANTICOL -> UID+BCC answered, but the PN533 reader's SELECT arrives as a bare `93` (no
CIU error flags) and no select completes - unknown whether that is the PN533 reader or
the PN532 emulator; needs another real reader (a PN532 one, or a phone).
**The WB-R can't be interrupted in target mode**: sending anything while a target
command is pending wedges it until replugged - libnfc's PN532 ACK-frame abort, the
CCID ABORT request, a USB reset, or simply the next process opening it (all
hardware-tested), and its Set Timeout (FF 00 41) is refused with 63 00. So the back-end
never sends while one is pending, and on close waits for any reader to be presented
(Ctrl-C again gives up; a hard kill can't be handled - replug). Note also that a raw
7-bit REQA sent through that path as an initiator wedges it.
- `pn532mitm` with a non-ACS READER side: when the EMULATOR is remote the READER only
  selects the real card and relays APDUs, so it now runs on any APDU reader (synthetic
  PN532 firmware/status replies; Type B sources presented as Type A, ATQA 0004 SAK 20).
  Verified on one host over loopback: TWN4 reading a Type B ePassport, ACR122U-WB-R
  `-f ccid` emulating, SCL3711 as the victim (SELECT AID + GET CHALLENGE relayed).
  Full `mrpkey` read through it (BAC, EF.COM/SOD/DG1/18 KB DG2/DG14, PA hashes OK).
  Relay timing: the victim's frame waiting time is set by the PN532's own ATS
  (`05 75 33 92 03`: FWI 9, ~155 ms - TgInitAsTarget only takes the historical bytes;
  no other way to raise FWI found yet).
  Two early runs stalled at a file's first 118-byte read: those replies took ~124 ms
  because send_data()'s three small writes hit Nagle + delayed ACK, 41 ms each way on
  loopback. With TCP_NODELAY and one write per message the worst relay is 55 ms
  (TWN4 + passport ~43 ms), 5/5 full reads. Across two hosts the network round trip
  comes out of the remaining ~100 ms. Once, the session didn't end when the victim
  left (no field drop seen, probably the TWN4's field reaching the emulator) - Ctrl-C.

## 15. Replacement Android target + "rfidiot" Android app
The current `READER_ANDROID` back-end (`rfidiot/pyandroid.py`, 2011, Lateral Security)
is dormant and broken under Python 3: it is a plain-text TCP server on port 4444 that a
companion Android app connects to, but `self.c.send("getUID\n")` sends a `str` where
Py3 sockets need `bytes` (TypeError on the first call), `select()` returns raw `recv`
bytes that are later string-concatenated, framing is newline-split with a fixed 1024-byte
`recv` (breaks on larger or newline-bearing responses), and `sendResults()` has a
`results`/`result` name bug. There is no matching open app in the repo.
Plan - rebuild it as two pieces:
- **Back-end (`READER_ANDROID`):** a clean Py3 transport. Binary-safe, length-framed
  messages (not newline-split); encode/decode at the socket edge; handle responses of
  any size; proper connect/teardown and timeouts. Keep the existing API surface
  (`select()` -> UID + ideally tag type / `sens_res` / `sel_res`, `sendAPDU()` /
  `send_apdu()`), so `ChAP`, `mrpkey`, `send_apdu`, `nfcid` work over it unchanged.
  Decide transport: TCP over Wi-Fi, or USB via `adb forward` (more reliable, no LAN).
- **"rfidiot" Android app:** the companion on the phone, speaking that protocol.
  - **Reader (PCD) role:** use Android's NFC `IsoDep`/`NfcA`/`NfcB` to read a card held
    to the phone and relay APDUs - the phone becomes the reader.
  - **Card-emulation (HCE) role:** Android Host Card Emulation can present a Type 4
    (ISO 14443-4) target with arbitrary AIDs and answer APDUs from the host - something
    neither the PN532 nor the PN533 UID limit allows cleanly. This would give a real
    EMULATOR and MITM back-end on commodity hardware (cf. sections 12/14), and HCE is
    not bound to the `08` first-UID-byte limit the PN53x target mode has (section 9).
    Caveat: stock Android HCE does not let an app set the UID (the NFC controller sends
    a random one), so a chosen UID still needs a rooted device or a patched controller.
  - Nice to have: show tag info / dumps on the phone, drive LF where the phone can't
    (it can't - HF only), act as the victim-side logger for MITM runs.

## 16. PC/SC MIFARE Classic via General Authenticate (FF 86) - **[DONE, partial hw]**
The generic PC/SC MIFARE path used the deprecated FF 88 authenticate and SCM-style key
slots (0x60), which modern CCID readers reject; fixed to load the key to volatile slot 0
(FF 82 00 00) and use PC/SC v2.01 General Authenticate (FF 86), with a full 16-byte block
read (FF B0 .. 10) instead of the SCM Le=01 size-probe. Unknown readers now default to
generic PC/SC, not OMNIKEY. ACS keeps acs_mifare_login; OMNIKEY/SCM keep the legacy FF 88.
Verified on an Elatec TWN4 (CCID firmware, -r 0): auth + read sectors 0 and 1, trailer,
wrong-key reject; ACR122U-WB-R (-f ccid) and tikitag (libnfc) confirmed unbroken (regression).
Still to verify when the hardware is to hand:
- **OMNIKEY CardMan 5321** (legacy FF 88 path, left untouched) - not used in any recorded
  session; check MIFARE auth/read still works on it, and that it is still detected as
  READER_OMNIKEY (name starts "OMNIKEY").
- a real **ACS ACR122U PICC over PC/SC** (-r), to exercise acs_mifare_login - the WB-R and
  tikitag both go via direct-CCID / libnfc instead, so that path was not exercised here.
- an **SCM SDI010** (legacy FF 88 + 0x60 slots), if one is ever available.

## 17. True UID emulation on libnfc PN53x (`emulateuid.py`) - **[DONE]**
The PN53x answers anticollision in hardware (AutoColl) from a 25-byte buffer holding
only 3 UID bytes, so `TgInitAsTarget` always presents `08` + 3 bytes (verified by
reading the CIU Config buffer back). The way round it, as in libnfc's
`nfc-emulate-uid`: once AutoColl has activated the chip (a full select plus one more
command), it stays an activated target relaying raw frames, and the host answers
REQA/WUPA, ANTICOL and SELECT itself (CRC handling off, SAK CRC added by hand).
Without that activation, host-sent replies never go out - a plain card-mode
Receive/Transmit without AutoColl does not work, and the activation bit is read-only.
Two ways to get the priming activation:
- retry (default): prime with SAK 20, so the real reader follows its select with a
  RATS; we never answer it, the reader's activation fails, and a reader that retries
  (PN532 InListPassiveTarget does) selects again - answered by the host, so its first
  reported UID is ours.
- `-p` primer: a second reader (ACR122U `ccid`, `twn4`, or a libnfc connstring) primes
  first, so the real reader sees our UID from its first poll - but only while the
  emulator never loses RF field (see below).
**Losing the RF field releases the activation** (libnfc `-10` NFC_ETGRELEASED): after
priming on the TWN4 with its field held on, lifting the SCL3711 clear released it at
once; put back, it reports plain timeouts but relays nothing, and the next field cycle
releases it again. It needs a fresh `initAsTarget`, i.e. `08`-priming again. So `-p`
can't prime on one reader and then be carried to another; the primer's field must
overlap the real reader's. (An earlier "survives 20 s field-off" result was the
ACR122U's RFConfiguration RF-off, which evidently doesn't drop the field enough for
the PN533 to notice.)
**TWN4 as real reader: does not work.** It primes us (its RATS, or a raw `3000` after
SAK 08), but it cycles its field at every SearchTag (and on SetRFOff / SetTagTypes),
which releases the activation, so it always reads the `08` priming UID. The TWN4 has no
lower-level REQA/anticollision call that would keep the field up.
Verified (SCL3711 emulating, ACR122U-WB-R as reader): 4-byte `DEADBEEF`, 7-byte
`04A1B2C3D4E5F6` (2 cascade levels), retry mode, and `-p ccid` with the ACR122U as both
primer and reader. Host replies take ~5 ms per step over USB; the ACR122U accepts that.
Remaining:
- a primer whose field overlaps the real reader's (e.g. both readers side by side) is
  untested; so is the TWN4 as primer for a PN532 real reader.
- libnfc-connstring primer (needs a second libnfc device) untested.
- other real readers: one that cycles its field between polls can't be used (see the
  TWN4); one that doesn't retry after a failed RATS needs `-p`; one with strict ISO timing (~86 us) may not accept host-timed replies at all.
- above the UID layer: RATS/ATS + T=CL and MIFARE Classic are not emulated (Crypto1
  isn't available in PN53x target mode).
- ACR122U (PN532) as the emulator via the direct-CCID path: not tried - note a raw
  7-bit REQA sent through that path wedges the ACR122U-WB-R until replugged.

### Why `emulateuid` stays separate from `pn532emulate` / `pn532mitm` (not a merge)
They are two mutually exclusive modes of the PN53x target, not a feature flag:
- `pn532emulate` / `pn532mitm`: the **chip** owns ISO 14443-3 (anticollision + CRC,
  and for Type 4 the T=CL block protocol via easy framing); the host trades APDUs.
  Consequence: the UID first byte is forced to `08`, but you get real card behaviour
  (Type 4 APDU relay, Type 2 reads).
- `emulateuid`: the **host** owns ISO 14443-3 (`targetHandleCRC(False)`, raw frames,
  host answers REQA/ANTICOL/SELECT by hand). Consequence: any UID, but nothing above
  the UID layer (RATS/APDUs are shown, not answered), and only via the AutoColl
  priming trick (retry, or a primer whose field overlaps the target reader's).
You cannot have both on one activation: either the chip answers anticollision (08 +
APDU relay) or the host does (custom UID, no higher layers). A "merge" is therefore a
second, incompatible plumbing with a different, fragile activation model - and it would
overload each tool's interface (against RFIDIOt's one-small-tool-per-task convention),
and risk the verified relay tools with experimental code. The convergence worth having
is the reverse of a merge: once host-anticollision **plus** host-side T=CL works (the
full relay below), that becomes a shared engine both a UID-aware emulator and the MITM
call - rather than cramming two paths into today's tools.

### 17a. Full relay: real UID **and** APDU relay on one chip - **[IN PROGRESS]**
Goal: host answers anticollision with a chosen UID (`emulateuid`'s raw-frame mode) AND
then runs the ISO 14443-4 block protocol (T=CL) on the target side - answer the RATS
with an ATS, relay each I-block's APDU to a real card on another reader, wrap the reply
back - so a reader sees our UID and talks to the real card. This is the thing a naive
"merge" would imply, but it is new work, not a refactor.
- Foundation: `emulateuid` already gets REQA->ATQA, ANTICOL->UID+BCC, SELECT->SAK on a
  libnfc PN53x (SCL3711), and the RATS then arrives as a raw frame (currently "not
  handled"). So target-side software T=CL is implementable on top: answer `E0xx` (RATS)
  with an ATS, then handle I-/R-/S-blocks (PCB block numbers, chaining, WTX) - the
  mirror of the reader-side `_tcl_exchange`.
- Milestones: (1) **[DONE]** answer RATS with an ATS and confirm the victim then sends
  an I-block APDU (stub reply); (2) **[DONE]** target-side T=CL framing (I-block, block
  toggle); (3) relay the APDU to a real card (reuse `pn532mitm`'s reader side) and
  return the reply; (4) **[DONE]** end-to-end with a chosen UID; (5) chaining + WTX for
  long responses (DG2), for a full mrpkey/BAC read. Prototype `relayuid.py` (branch `full-relay`): verified (1)+(2) on an
  SCL3711 emulating + ACR122U-WB-R (`-f ccid`) victim - UID CAFE1234 read with our ATS
  0578808000, GET CHALLENGE relayed to the stub and the reply (08..9000) returned. Milestones
  3+4 (`-c eccid` relay to a real card) verified too: victim on the ACR122 saw UID
  CAFE1234 and, through SCL3711->Elatec, selected the real passport's eMRTD AID
  (9000) and got a real GET CHALLENGE - single-block APDUs only (milestone 5 next).
- Constraints: SCL3711 (PN533) works only in RAW target mode here (it cannot be an
  easy-framing Type 4 target); the ACR122U over `-f ccid` can't yet because its custom
  UID SELECT arrives as a bare `93` (unresolved - section 14). MIFARE Classic stays out
  of scope (Crypto1 not available in target mode).
