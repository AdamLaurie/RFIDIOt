#!/bin/sh

xterm -T 'Frosch port /dev/ttyUSB0' -e python ./multiselect.py -s 9600 -l /dev/ttyUSB0 -R RFIDIOt.rfidiot.READER_FROSCH &
