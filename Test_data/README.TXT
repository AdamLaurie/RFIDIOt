
Mifare test card images in Proxmark and Flipper format

    Mifare 1k 4 byte ID : 01 23 45 67
	Mf1k_4b_test.bin Mf1k_4b_test.nfc

    Mifare 1k 7 byte ID:  00 11 22 33 44 55 66
	Mf1k_7b_test.bin Mf1k_7b_test.nfc

Card data Sector contains the Sector numbers :

    Block  0: 01 23 45 67 00 08 04 00 FF FF FF FF FF FF FF FF
    Block  1: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    Block  2: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    Block  3: FF FF FF FF FF FF FF 07 80 69 FF FF FF FF FF FF

    Block  4: 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11
    Block  5: 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11
    Block  6: 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11
    Block  7: FF FF FF FF FF FF FF 07 80 69 FF FF FF FF FF FF

    Block  8: 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22
    Block  9: 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22
    Block 10: 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22
    Block 11: FF FF FF FF FF FF FF 07 80 69 FF FF FF FF FF FF

    ...

    Block 56: FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    Block 57: FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    Block 58: FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    Block 59: FF FF FF FF FF FF FF 07 80 69 FF FF FF FF FF FF

    Block 60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    Block 61: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    Block 62: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    Block 63: FF FF FF FF FF FF FF 07 80 69 FF FF FF FF FF FF

---

Throwawqay Demo code for AID-lookup:
    AID-lookup-demo.py
    AID-data.csv
    RID-data.csv

