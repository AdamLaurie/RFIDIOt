
Mifare test card images in Proxmark and Flipper format

File formats

&nbsp;&nbsp;&nbsp;nfc : Flipper Zero Format (ascii)<br>
&nbsp;&nbsp;&nbsp;mct : [MifareClassicTool](https://play.google.com/store/apps/details?id=de.syss.MifareClassicTool&hl=en_US) (ascii)<br>
&nbsp;&nbsp;&nbsp;bin : Proxmark/Binary Format<br>



#### [Mf1k_4b-FF-keys](Mf1k_4b-FF-keys.nfc) ####

Mf1k_4b-FF-keys
    Mifare 1k 4 byte ID : 01 23 45 67

    Card data Sector contains the Sector numbers 

<details><summary>More Info:</summary>

```
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

    ... And So On ...

    Block 56: EE EE EE EE EE EE EE EE EE EE EE EE EE EE EE EE
    Block 57: EE EE EE EE EE EE EE EE EE EE EE EE EE EE EE EE
    Block 58: EE EE EE EE EE EE EE EE EE EE EE EE EE EE EE EE
    Block 59: FF FF FF FF FF FF FF 07 80 69 FF FF FF FF FF FF

    Block 60: FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    Block 61: FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    Block 62: FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    Block 63: FF FF FF FF FF FF FF 07 80 69 FF FF FF FF FF FF

```

</details>

---

#### [Mf1k_4b-Mixed-Pi](Mf1k_4b-Mixed-Pi.nfc) ####

Mifare 1k 4 byte ID : 31 41 59 26

Card data Sector 0->14 contains the Sector numbers in Hex
Sector 15 contains the value for Pi 

The Keys sould be "guessed" by default dict in [readmifaresimple.py](../readmifaresimple.py)

<details><summary>Sector Keys:</summary>

```
    Sector: 0 KeyA: FFFFFFFFFFFF KeyB: FFFFFFFFFFFF
    Sector: 1 KeyA: A0A1A2A3A4A5 KeyB: 111111111111
    Sector: 2 KeyA: 222222222222 KeyB: B0B1B2B3B4B5
    Sector: 3 KeyA: ABCDEF012345 KeyB: 543210FEDCBA
    Sector: 4 KeyA: 4D3A99C351DD KeyB: 444444444444
    Sector: 5 KeyA: 555555555555 KeyB: 1A982C7E459A
    Sector: 6 KeyA: D3F7D3F7D3F7 KeyB: 666666666666
    Sector: 7 KeyA: AABBCCDDEEFF KeyB: 777777777777
    Sector: 8 KeyA: 888888888888 KeyB: A0A1A2A3A4A5
    Sector: 9 KeyA: FFFFFFFFFFFF KeyB: FFFFFFFFFFFF
    Sector: 10 KeyA: FFFFFFFFFFFF KeyB: FFFFFFFFFFFF
    Sector: 11 KeyA: FFFFFFFFFFFF KeyB: FFFFFFFFFFFF
    Sector: 12 KeyA: FFFFFFFFFFFF KeyB: FFFFFFFFFFFF
    Sector: 13 KeyA: FFFFFFFFFFFF KeyB: FFFFFFFFFFFF
    Sector: 14 KeyA: FFFFFFFFFFFF KeyB: FFFFFFFFFFFF
    Sector: 15 KeyA: 314159265358 KeyB: 853562951413
```

</details>
