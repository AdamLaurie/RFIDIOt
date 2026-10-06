/* RFIDIOt.py - RFID IO tools for python
 *
 * Adam Laurie <adam@algroup.co.uk>
 * http://rfidiot.org/
 *
 * This code is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

Copyright (c) 2006-2026 Adam Laurie <adam@algroup.co.uk>

*** This is the Python 3 version of RFIDIOt. ***

Run everything with python3. The original Python 2.7 code is preserved on the
'python2.7' branch and tagged 'v1.0-python2.7' - it will not run under python3,
and this version will not run under python2.

With huge thanks to Pete Shipley (evilpete), who did the bulk of the Python 3
port and contributed a great deal to the python3 branch that became this release.

q: What is RFIDIOt?
a: A collection of tools and libraries for exploring RFID/NFC technology, written
in python.

q: Why RFIDIOt?
a: I like silly puns. Also, I'm coming at this from an idiot's point of view:
I know nothing about RFID tags, and even less about python. As such, I felt a
complete idiot when I started. :)

q: How can I contribute?
a: Send me patches, info, new tools, coffee, money, drugs and/or a Miles Davis song :)

q: What hardware is supported?
a:
  - libnfc readers (PN53x based: ACR122U, SCL3711, etc.) - use '-R READER_LIBNFC'
    or '-f <n>', and see '-N' to list them. libnfc must be installed separately.
  - PC/SC readers via pyscard + pcscd ('-R READER_PCSC', auto-detects the
    subtype: ACS / OMNIKEY / SCM). This is the default. Both T=0 and T=1 cards
    are handled. Note: the OMNIKEY CardMan 5321's *contact* slot works with the
    open libccid driver, but its *contactless* (13.56 MHz) interface needs HID's
    proprietary OMNIKEY driver (ifdokccid) - libccid only exposes the contact
    slot. With the HID driver installed the contactless interface appears as a
    second PC/SC slot, i.e. reader index 1 ('-r 1').
  - the original ACG and Frosch serial readers ('-R READER_ACG' / '-R READER_FROSCH',
    serial port via '-l', e.g. /dev/ttyUSB0).
  Run any tool with '-h' for the full list of options.

q: How do I install it?
a:
  pip install -r requirements.txt       # pycryptodome, pyscard, cryptography
  sudo python3 ./setup.py install
System packages: install libnfc for libnfc readers; for PC/SC readers install
the daemon and CCID driver and make sure the daemon is running, e.g. on Debian/
Ubuntu:
  sudo apt install pcscd libccid pcsc-tools
Some tools have extra needs: mrpkey.py uses PIL/Pillow to display passport
photos and openssl for certificate handling; jcoptool.py needs pyasn1.

q: Anything new in the Python 3 version?
a: Besides the port itself:

ChAP.py ("Chip And PIN") is a contactless/contact EMV reader that works over both
PC/SC and libnfc ('-n'). It walks the card (PPSE -> AID -> GPO -> records), decodes
the EMV BER-TLV (AIP, AFL, CVM list, CDOL/DDOL, Track 2 split into PAN / expiry /
service code, cryptogram information, etc.) and reads the card's transaction log
(amount / date / time / currency / ATC per entry). With '-c' it performs full
offline data authentication - it recovers the CA -> Issuer -> ICC certificate chain
(a bundled table of 26 scheme CA keys: Visa, Mastercard, Amex, CB, JCB, Discover,
UnionPay, RuPay, each checked against its EMVCo CAPK checksum) and then verifies the
card's signature by whichever method the card supports:
  - SDA  - Signed Static Application Data (tag 93)
  - DDA  - INTERNAL AUTHENTICATE with a random challenge (contact)
  - fDDA - the fast-DDA signature returned in the GPO (contactless)
  - CDA  - the signature combined with the cryptogram ('-g' sends GENERATE AC;
           intrusive - it increments the card's ATC)
Companion/alias applications (e.g. LINK) verify under the primary scheme's CA. The
recovery is self-validating, so a wrong or missing key fails cleanly. Run with no
PIN argument to stay read-only; a PIN argument sends an offline VERIFY (plaintext,
or RSA-enciphered with '-E'), which updates the PIN Try Counter.

mrpkey.py reads ePassports and passiveauth.py performs Passive Authentication
(data-group integrity + DS/CSCA trust) against a public CSCA master list, flagging a
passport SAFE / TAMPERED / UNTRUSTED. rfidiot-cli.py also reads contactless EMV.

q: So what exactly is here?
a: Please see http://www.rfidiot.org/documentation.html
