#!/bin/sh

xterm -T 'Frosch port /dev/ttyS0' -e python ./multiselect.py -s 9600 -l /dev/ttyS0 -R RFIDIOt.rfidiot.READER_FROSCH &
