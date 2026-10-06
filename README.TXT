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
    subtype: ACS / OMNIKEY / SCM). This is the default.
  - the original ACG and Frosch serial readers ('-R READER_ACG' / '-R READER_FROSCH',
    serial port via '-l', e.g. /dev/ttyUSB0).
  Run any tool with '-h' for the full list of options.

q: How do I install it?
a:
  pip install -r requirements.txt       # pycryptodome, pyscard, cryptography
  sudo python3 ./setup.py install
Install libnfc for libnfc readers, and run pcscd for PC/SC readers. Some tools
have extra needs (e.g. mrpkey.py uses PIL/Pillow to display passport photos,
and openssl for certificate handling).

q: Anything new in the Python 3 version?
a: Besides the port itself: rfidiot-cli.py and ChAP.py read contactless EMV cards
over libnfc (ChAP.py '-c' recovers and verifies the SDA/DDA certificate chain
against a CA master list), mrpkey.py reads ePassports and passiveauth.py performs
Passive Authentication (data-group integrity + DS/CSCA trust) against a public
CSCA master list, flagging a passport SAFE / TAMPERED / UNTRUSTED.

q: So what exactly is here?
a: Please see http://www.rfidiot.org/documentation.html
