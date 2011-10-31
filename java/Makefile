#
# Makefile for JAVA applet jcop_set_atr_hist
#
# Adam Laurie, 2009
# http://rfidiot.org
#
# See inline comments for instructions on how to set up your environment
#

APPLET_PACKAGE=jcop_set_atr_hist
APPLET_CLASS=JCOPSetATRHist
PACKAGE_AID=0xDC:0x44:0x20:0x06:0x06
APPLET_AID=0xDC:0x44:0x20:0x06:0x06:0x07
APPLET_AID_LENGTH=6

#JAVA_HOME=/usr/local/java/jdk
JAVA=$(JAVA_HOME)/bin/java
JAVAC=$(JAVA_HOME)/bin/javac
JAVADOC=$(JAVA_HOME)/bin/javadoc

# Java Card Kit must be version 2.2.1 for gpshell
# and can be  downloaded here:
#
# http://java.sun.com/javacard/downloads/index.jsp
#
# download 'Java Card 2.2.1 Development Kit' and set the following variable (JCZIP)
# to the zipfile name, then run 'make jckit'
#
JCZIP=java_card_kit-2_2_1-linux-dom.zip
JCPATH=./java_card_kit-2_2_1

#
# Global Platform API can be found here:
#
# http://www.globalplatform.org/specificationscard.asp
#
# download 'Java Card Export File for Card Specification v2.1' from the
# 'Archived Card Documentation' section. Make sure you choose v2.1 and NOT v2.1.1,
# and set the following variable (GPZIP) to the zipfile name, then run 'make gpapi'
# (GPZIP and GPDIR were correct at time of release, so should not need changing)
#
GPZIP=Java_Export_v2_1_or_v2_1_1_API.zip
GPDIR=GP_exportA00000015100
#GPDIR=$(shell echo $(GPZIP) | cut -f1 -d'.')
GPLIB=./gp21.jar
GPEXPORTPATH=./gp21

JCAPI=$(JCPATH)/lib/api.jar
JCCONV=$(JCPATH)/lib/converter.jar
JCVERIFIER=$(JCPATH)/lib/offcardverifier.jar
EXPORTPATH=$(JCPATH)/api_export_files

#
# GPShell can be got here:
#
# http://sourceforge.net/project/showfiles.php?group_id=143343&package_id=159897
#
GPSHELL= "gpshell"
GPSHELL_SCRIPT="jcop_set_atr_hist.gpsh"
GPSHELL_UNINSTALL_SCRIPT="jcop_delete_atr_hist.gpsh"

all: jcop_set_atr_hist.cap

classes: build
	$(JAVAC)\
	   -g\
	   -classpath $(JCAPI):$(GPLIB):.\
	   -d build\
	   -sourcepath ./src \
	   -source 1.2 \
	   -target 1.2 \
	   src/jcop_set_atr_hist/JCOPSetATRHist.java

jcop_set_atr_hist.cap: classes
	$(JAVA)\
	   -classpath $(JCCONV):$(JCVERIFIER)\
	   com.sun.javacard.converter.Converter\
	      -classdir build\
	      -exportpath $(EXPORTPATH):$(GPEXPORTPATH):.\
	      -applet $(APPLET_AID) $(APPLET_CLASS)\
	      -d build\
	      -out CAP\
	      -v\
              -debug \
	      $(APPLET_PACKAGE) $(PACKAGE_AID) 1.0
	      cp build/jcop_set_atr_hist/javacard/jcop_set_atr_hist.cap .

build:
	@if ! test -e gp21.jar ; then echo "You need to set up your Global Platform environment! Read Makefile comments for help." ; exit 1 ; fi
	@if ! test -e $(JCCONV); then echo "You need to set up your Java Card Kit! Read Makefile comments for help."; exit 1; fi
	mkdir -p build

install:
	$(GPSHELL) $(GPSHELL_SCRIPT)

uninstall:
	$(GPSHELL) $(GPSHELL_UNINSTALL_SCRIPT)

clean:
	rm -f jcop_set_atr_hist.cap
	rm -rf build

gpapi:
	@if ! test -e $(GPZIP) ; then echo "Can't find Global Platform API zipfile! Read Makefile comments for help." ; exit 1 ; fi
	@unzip -x $(GPZIP)
	cd $(GPDIR) && jar cvf ../gp21.jar *
	mv $(GPDIR) gp21

jckit:
	@if ! test -e $(JCZIP) ; then echo "Can't find Java Card Kit zipfile! Read Makefile comments for help." ; exit 1 ; fi
	@unzip -x $(JCZIP)
