/**
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

/* 15 byte buffer for ATR Historical Bytes (ATS) must be a global */

public class ATRGlobal {
	public static byte[] ATR_HIST= {(byte) 0x00,(byte) 0x00,(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				       	(byte) 0x00,(byte) 0x00,(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
					(byte) 0x00,(byte) 0x00,(byte) 0x00};
}
