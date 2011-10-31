# Makefile for uploading vonJeek epassport emulator and Mifare acccess applet
# http://freeworld.thc.org/thc-epassport/
#
# gpshell can be found here:
# http://sourceforge.net/project/showfiles.php?group_id=143343&package_id=159897
#
# blank JCOP cards can be got here:
# (note vonJeek applet requires 72K card)
# http://www.rfidiot.org/
#
# This makefile by Adam Laurie, 2008

# GPShell...
GPSHELL= "gpshell"
GPSHELL_VONJEEK_SCRIPT="upload2jcop.gpsh"
GPSHELL_VONJEEK_NOKIA_SCRIPT="upload2nokia.gpsh"
GPSHELL_MIFARE_SCRIPT="jcop_mifare_access.gpsh"
GPSHELL_ATR_SCRIPT="jcop_set_atr_hist.gpsh"
GPSHELL_ATR_UNINSTALL_SCRIPT="jcop_delete_atr_hist.gpsh"
GPSHELL_NOKIA_MIFARE_SCRIPT="nokia_jcop_mifare_access.gpsh"

# install passport applet
install-passport:
	# first clean the script of nasty windows <CR>s
	tr -d '\r' < $(GPSHELL_VONJEEK_SCRIPT) > /tmp/$(GPSHELL_VONJEEK_SCRIPT)
	$(GPSHELL) /tmp/$(GPSHELL_VONJEEK_SCRIPT)

# install passport applet to Nokia
# phone must have been unlocked with the unlock midlet:
# Nokia NFC Unlock Service MIDlet - http://www.forum.nokia.com
install-passport-nokia:
	tr -d '\r' < $(GPSHELL_VONJEEK_NOKIA_SCRIPT) > /tmp/$(GPSHELL_VONJEEK_NOKIA_SCRIPT)
	$(GPSHELL) /tmp/$(GPSHELL_VONJEEK_NOKIA_SCRIPT)

# install mifare access applet
install-mifare:
	$(GPSHELL) $(GPSHELL_MIFARE_SCRIPT)

# install ATR History applet
install-atr:
	cd java && $(GPSHELL) $(GPSHELL_ATR_SCRIPT)

# delete ATR History applet
uninstall-atr:
	cd java && $(GPSHELL) $(GPSHELL_ATR_UNINSTALL_SCRIPT)
