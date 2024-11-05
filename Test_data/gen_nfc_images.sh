

#    nfc_flip2prox.py [-f output_format] input_filename [output_filename]
#
#    Valid formats:
#	    eml:	proxmark emulator
#	    bin:	proxmark/Chameleon bin format
#	    mct:	MIFARE Classic Tool
#	    mfj:	MIFARE Classic Tool Json
#	    json:	proxmark/Chameleonn Json format


./nfc_flip2prox.py -f bin Mf1k_4b-FF-keys.nfc Mf1k_4b-FF-keys.bin
./nfc_flip2prox.py -f mct Mf1k_4b-FF-keys.nfc Mf1k_4b-FF-keys.mct


./nfc_flip2prox.py -f bin Mf1k_4b-Mixed-Pi.nfc Mf1k_4b-Mixed-Pi.bin
./nfc_flip2prox.py -f mct Mf1k_4b-Mixed-Pi.nfc Mf1k_4b-Mixed-Pi.mct

