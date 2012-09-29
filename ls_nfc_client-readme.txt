/* LS_NFC_CLient - Android Network NFC Client for use with RFIDIOt
 *
 * Nick von Dadelszen <nick@lateralsecurity.com>
 * https://www.lateralsecurity.com/
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
 *
 * Copyright (c) 2011 Lateral Security
 */

LS_NFC_CLient is an Android application that detects an NFC card and makes a network connection to obtain commands (APDUs) to run on that card.  It works by registering an intent for detection of ISODEP NFC cards, and then connecting to the server defined the application settings.  This can be changed in the client UI.


For the server component, you can use netcat to listen on the port and send APDUs manually.  Or you can use RFIDIOt with the pyandroid patch to send commands to the card.

The application has been tested on a Nexus S with the following types of cards:
- Electronic passports
- Paypass creditcards
- OTher ISO 14443 cards

You can also use RFIDIOt to make calls ro LS_NFC_Client by setting -R RFIDIOt.rfidiot.READER_ANDROID or modifying the RFIDIOtconfig.py

