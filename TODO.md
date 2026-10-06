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
