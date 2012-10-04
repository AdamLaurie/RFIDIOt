from distutils.core import setup, Extension

packages= ['RFIDIOt']

scripts = ['cardselect.py', 'ChAP.py', 'copytag.py', 'demotag.py', 
	   'eeprom.py', 'fdxbnum.py', 'formatmifare1kvalue.py', 'froschtest.py', 'hidprox.py', 'hitag2brute.py',
	   'hitag2reset.py', 'isotype.py', 'jcopmifare.py', 'jcopsetatrhist.py', 'jcoptool.py',
	   'lfxtype.py', 'loginall.py', 'mifarekeys.py', 'mrpkey.py', 'multiselect.py', 'pn532emulate.py', 
	   'pn532mitm.py', 'pn532.py', 'q5reset.py', 'readlfx.py', 'readmifare1k.py', 
	   'readmifaresimple.py', 'readmifareultra.py', 'readtag.py', 'send_apdu.py', 'sod.py', 'transit.py',
	   'unique.py', 'writelfx.py', 'writemifare1k.py', 'testacg.sh', 'testlahf.sh'
	]

setup  (name        = 'RFIDIOt',
        version     = '1.0',
        description = "RFID IO tools",
        author = 'Adam Laurie',
        author_email = 'adam@algroup.co.uk',
	packages= packages,
        scripts = scripts
       )

