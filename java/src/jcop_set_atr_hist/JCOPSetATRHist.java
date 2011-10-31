/**
*  JCOPSetATRHist.java - set ATR History bytes on JCOP cards
*
*     Must be installed as "default selectable" (priv mode 0x04).
*   
*     Adam Laurie <adam@algroup.co.uk>
*     http://rfidiot.org/
*   
*     This code is copyright (c) Adam Laurie, 2009, All rights reserved.
*     For non-commercial use only, the following terms apply - for all other
*     uses, please contact the author:
*   
*       This code is free software; you can redistribute it and/or modify
*       it under the terms of the GNU General Public License as published by
*       the Free Software Foundation; either version 2 of the License, or
*       (at your option) any later version.
*   
*       This code is distributed in the hope that it will be useful,
*       but WITHOUT ANY WARRANTY; without even the implied warranty of
*       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*       GNU General Public License for more details.
*/


package jcop_set_atr_hist;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.Util;
import org.globalplatform.GPSystem;

public class JCOPSetATRHist extends Applet 
{
	public static void install(byte[] bArray, short bOffset, byte bLength) 
		{
		new jcop_set_atr_hist.JCOPSetATRHist().register(bArray, (short) (bOffset + 1),
				bArray[bOffset]);
		}

	public void process(APDU apdu) 
		{
		byte[] buffer = apdu.getBuffer();
		byte ins = buffer[ISO7816.OFFSET_INS];

		if (selectingApplet()) 
			{
			return;
			}

		byte len = buffer[ISO7816.OFFSET_CDATA];
		// Max ATS is 15 bytes
		if (len > (byte) 15)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		Util.arrayCopy(buffer,(short) (ISO7816.OFFSET_CDATA + 1),ATRGlobal.ATR_HIST,(short) 0x00,len);	
		switch (ins) 
			{
			case (byte) 0xAB:
				if( ! org.globalplatform.GPSystem.setATRHistBytes(ATRGlobal.ATR_HIST,(short) 0x00, len ))
					ISOException.throwIt(ISO7816.SW_UNKNOWN);
				return;
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			}
		}
}
