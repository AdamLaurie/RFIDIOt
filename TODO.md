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
- `ChAP.py` `CA_PUBLIC_KEYS` has verified AMEX `A000000025`/`10` and Mastercard
  `A000000004`/`06`. Add **Visa** (`A000000003`) and others when a card is tapped
  (ChAP prints "no CA public key for RID ... index ..."); each key self-validates
  via the `6A..BC` + SHA-1 recovery before trusting it.

## 5. ChAP.py feature enhancements (implement in order)
Survey of what ChAP.py could do that it doesn't yet. Work these one at a time,
top to bottom.

1. **[DONE] Live card authentication (complete what `-c` starts).** `-c` now runs,
   after the cert chain, SDA + DDA/fDDA against the recovered keys:
   - **SDA** - `verify_sda()` recovers Signed Static Application Data (tag 93)
     against the recovered Issuer key, rebuilding the authenticated static data
     from the AFL offline records (SFI<=10 template-stripping rule) + the 9F4A tag
     list's AIP. *Hardware-untested positive: both test cards are DDA-only (no tag
     93); need a pre-2010 SDA card to exercise a VERIFIED result.*
   - **DDA (contact)** - `verify_dda()` sends INTERNAL AUTHENTICATE with a random
     UN via the DDOL (9F49), recovers 9F4B, verifies. VERIFIED on Visa + Amex.
   - **fDDA (contactless)** - verifies the 9F4B returned inline in the GPO. The
     Visa qVSDC hash covers UN || Amount (9F02) || Currency (5F2A) || Card
     Authentication Related Data (9F69). VERIFIED on a contactless Visa.
   Also fixed two general bugs: the GPO template body offset for long (>127-byte)
   BER lengths, and storing the AIP from a Format-1 GPO into EMVData[0x82].
2. **Transaction log reading.** Currently fetches LOG FORMAT (9F4F) and only
   hexprints it. Follow Log Entry (9F4D) -> SFI + record count, READ RECORD the log
   SFI, decode each entry per the format template (amount/date/time/currency/ATC).
   Fully read-only; scaffolding half-exists.
3. **Fill in the tag dictionary.** Missing (shown as "Unknown TAG"): 9F27
   (Cryptogram Information Data), 9F6C (Card Transaction Qualifiers), 9F6E (Form
   Factor Indicator / 3rd-party), 9F10 (Issuer Application Data), 9F6B (contactless
   MSD Track 2), 9F5A (Application Program ID), 9F4F (Log Format), 9F13 (Last Online
   ATC), 9F17 (PIN Try Counter).
4. **Bug: 0x9F66 is mislabeled** "Card Production Life Cycle" (that's 9F7F). 9F66 is
   **Terminal Transaction Qualifiers (TTQ)**. Correct it.
5. **Decode Track 2 into fields** - split the raw Track 2 Equivalent into PAN /
   expiry / service code (decode the 3-digit service code) / discretionary data.
   Same for 9F27 CID bits (ARQC/TC/AAC).
6. **GENERATE AC** (opt-in, intrusive).** Code exists but is commented out (~L1042).
   Running a transaction to get an ARQC/TC/AAC **increments the ATC** and writes card
   state - put it behind an explicit flag + warning, like the PIN path.
7. **Enciphered offline PIN** - `verify_pin()` only does plaintext; add RSA-enciphered
   PIN using the recovered ICC key.

Lower priority:
- JSON/structured output (library already has a `-j` Json global ChAP ignores).
- Final one-line card summary (scheme, masked PAN, expiry, cardholder, CVMs, auth
  result).
- Load `CA_PUBLIC_KEYS` from an external file instead of editing source (ties into #4
  above).
