#!/usr/bin/python


#  jcoptool.py - JCOP card toolkit
#  
#  Adam Laurie <adam@algroup.co.uk>
#  http://rfidiot.org/
# 
#  This code is copyright (c) Adam Laurie, 2009, All rights reserved.
#  For non-commercial use only, the following terms apply - for all other
#  uses, please contact the author:
#
#    This code is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This code is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#

import rfidiot
import sys
import os
import string
from Crypto.Cipher import DES3
from Crypto.Cipher import DES
from pyasn1.codec.ber import decoder

try:
        card= rfidiot.card
except:
	print "Couldn't open reader!"
        os._exit(True)

args= rfidiot.args
Help= rfidiot.help

# fixed values required by JCOP applet
CLA= '80'
P1= '00'
P2= '00'

templates=	{
	   	'66':'Card Data',
	   	'73':'Card Recognition Data',
	   	}

tags=	{
	'06':'OID',
	'60':'Application tag 0 - Card Management Type and Version',
	'63':'Application tag 3 - Card Identification Scheme',
	'64':'Application tag 4 - Secure Channel Protocol of the Issuer Security Domain and its implementation options',
	'65':'Application tag 5 - Card configuration details',
	'66':'Application tag 6 - Card / chip details',
	'67':'Application tag 7 - Issuer Security Domain\'s Trust Point certificate information',
	'68':'Application tag 8 - Issuer Security Domain certificate information',
	}

registry_tags= 	{
		'4F':'AID',
		'9F70':'Life Cycle State',
		'C5':'Privileges',
		'C4':'Application\'s Executable Load File AID',
		'CE':'Executable Lod File Version Number',
		'84':'First or only ExecutableModule AID',
		'CC':'Associated Security Domain\'s AID',
		}

card_status=	{
		'80':'Issuer Security Domain',
		'40':'Applications and Supplementary Security Domains',
		'20':'Executable Load Files',
		'10':'Executable Load Files and their Executable Modules',
		}

# life cycle state must be masked as bits 4-7 (bit numbering starting at 1) are application specific
application_life_cycle_states= 	{
				'01':'LOADED',
				'03':'INSTALLED',
				'07':'SELECTABLE',
				'83':'LOCKED',
				'87':'LOCKED',
				}

executable_life_cycle_states= 	{
				'01':'LOADED',
				}

security_domain_life_cycle_states= 	{
					'03':'INSTALLED',
					'07':'SELECTABLE',
					'0F':'PERSONALIZED',
					'83':'LOCKED',
					'87':'LOCKED',
					'8B':'LOCKED',
					'8F':'LOCKED',
					}
					

card_life_cycle_states=	{
			'01':'OP_READY',
			'07':'INITIALIZED',
			'0F':'SECURED',
			'7F':'CARD_LOCKED',
			'FF':'TERMINATED',
			}

targets= 	{
		'00':'Unknown',
		'01':'SmartMX',
		'03':'sm412',
		}

fuse_state=	{
		'00':'Not Fused',
		'01':'Fused',
		}

manufacturers= 	{
		'PH':'Philips Semiconductors',
		'NX':'NXP',
		}

privilege_byte_1=	{
			'80':'Security Domain',
			'C0':'DAP Verification',
			'A0':'Delegated Management',
			'10':'Card Lock',
			'08':'Card Terminate',
			'04':'Card Reset',
			'02':'CVM Management',
			'C1':'Mandated DAP Verification',
			}

def decode_jcop_identify(data, padding):
	fabkey= data[0:2]
	patch_id= data[2:4]
	target= data[4:6]
	mask_id= data[6:8]
	custom_mask= data[8:16]
	mask_name= data[16:28]
	fuse= data[28:30]
	rom_info= data[30:42]

	manufacturer= card.ToBinary(mask_name[0:4])
	manufacture_year= card.ToBinary(mask_name[4:6])
	manufacture_week= card.ToBinary(mask_name[6:10])
	manufacture_mask= ord(card.ToBinary(mask_name[10:12])) - 64
	

	print padding + 'FABKEY ID:       %s' % fabkey
	print padding + 'PATCH ID:        %s' % patch_id
	print padding + 'TARGET ID:       %s' % target + ' (' + targets[target] + ')'
	print padding + 'MASK ID:         %s' % mask_id + ' (Mask %s)' % int(mask_id,16)
	print padding + 'CUSTOM MASK:     %s' % custom_mask + ' (%s)' % card.ReadablePrint(card.ToBinary(custom_mask))
	print padding + 'MASK NAME:       %s' % card.ToBinary(mask_name)
	print padding + 'FUSE STATE:      %s' % fuse + ' (' + fuse_state[fuse] + ')'
	print padding + 'ROM INFO:        %s' % rom_info + ' (Checksum)'
	print padding + 'COMBO NAME:      %s-m%s.%s.%s-%s' % (targets[target], mask_id, fabkey, patch_id, card.ToBinary(mask_name))
	print padding + 'MANUFACTURER:    %s' % manufacturers[manufacturer]
	print padding + 'PRODUCED:        Year %s, Week %s, Build %d' % (manufacture_year, manufacture_week, manufacture_mask)

def decode_jcop_lifecycle(data, padding):
	ic_fab= data[0:4]
	ic_type= data[4:8]
	os_id= data[8:12]
	os_release_date= data[12:16]
	os_release_level= data[16:20]
	ic_fab_date= data[20:24]
	ic_serial= data[24:32]
	ic_batch= data[32:36]
	ic_mod_fab= data[36:40]
	ic_mod_pack_date= data[40:44]
	icc_man= data[44:48]
	ic_embed_date= data[48:52]
	ic_pre_perso= data[52:56]
	ic_pre_perso_date= data[56:60]
	ic_pre_perso_equip= data[60:68]
	ic_perso= data[68:72]
	ic_perso_date= data[72:76]
	ic_perso_equip= data[76:84]
	
	print
	print padding + 'IC Fabricator                       %s' % ic_fab
	print padding + 'IC Type                             %s' % ic_type
	print padding + 'OS ID                               %s' % os_id
	print padding + 'OS Release Date                     %s' % os_release_date
	print padding + 'OS Release Level                    %s' % os_release_level
	print padding + 'IC Fabrication Date                 Year %s Day %s' % (ic_fab_date[0], ic_fab_date[1:4])
	print padding + 'IC Serial Number                    %s' % ic_serial
	print padding + 'IC Batch Number                     %s' % ic_batch
	print padding + 'IC Module Fabricator                %s' % ic_mod_fab
	print padding + 'IC Module Packaging Date            Year %s Day %s' % (ic_mod_pack_date[0], ic_mod_pack_date[1:4])
	print padding + 'ICC Manufacturer                    %s' % icc_man
	print padding + 'IC Embedding Date                   Year %s Day %s' % (ic_embed_date[0], ic_embed_date[1:4])
	print padding + 'IC Pre-Personalizer                 %s' % ic_pre_perso
	print padding + 'IC Pre-Personalization Date         %s' % ic_pre_perso_date
	print padding + 'IC Pre-Personalization Equipment    %s' % ic_pre_perso_equip
	print padding + 'IC Personalizer                     %s' % ic_perso
	print padding + 'IC Personalization Date             Year %s Day %s' % (ic_perso_date[0], ic_perso_date[1:4])
	print padding + 'IC Personalization Equipment        %s' % ic_perso_equip

def decode_privileges(data):
	print '(',
	multiple= False
	try:
		for mask in privilege_byte_1.keys():
			if (int(data[0:2],16) & int(mask,16)) == int(mask,16):
				if multiple:
					print '/',
				print privilege_byte_1[mask],
				multiple= True
	except:
		print ')',
		return
	print ')',

# check privilege byte 0 to see if we're a security domain
def check_security_domain(data):
	length= int(data[2:4],16) * 2
	i= 4
	while i < length + 4:
		for item in registry_tags.keys():
			if data[i:i+len(item)] == item:
				itemlength= int(data[i+len(item):i+len(item)+2],16) * 2
				if item == card.GP_REG_PRIV:
					itemdata= data[i+len(item)+2:i+len(item)+2+itemlength]
					if (int(itemdata[0:2],16) & 0x80) == 0x80:
						return True
				i += itemlength + len(item) + 2
	return False

def decode_gp_registry_data(data, padding, filter):
	if not data[0:2] == card.GP_REG_DATA:
		return False, ''
	states= application_life_cycle_states
	if filter == card.GP_FILTER_ISD:
		states= card_life_cycle_states
	if filter == card.GP_FILTER_ASSD:
		states= application_life_cycle_states					
	if filter == card.GP_FILTER_ELF:
		states= executable_life_cycle_states
	# check if this is a security domain (not set up right, so disabled!)
	#if check_security_domain(data):
	#	states= security_domain_life_cycle_states
	length= int(data[2:4],16) * 2
	i= 4
	while i < length + 4:
		decoded= False
		for item in registry_tags.keys():
			if data[i:i+len(item)] == item:
				if not item == card.GP_REG_AID:
					print ' ',
				itemlength= int(data[i+len(item):i+len(item)+2],16) * 2
				itemdata= data[i+len(item)+2:i+len(item)+2+itemlength]
				print padding, registry_tags[item]+':', itemdata,
				if item == card.GP_REG_LCS:
					if filter == card.GP_FILTER_ASSD:
						# mask out application specific bits
						itemdata= '%02x' % (int(itemdata,16) & 0x87)
					print '( '+states[itemdata]+' )',
				if item == card.GP_REG_PRIV:
					decode_privileges(itemdata)
				decoded=  True
				i += itemlength + len(item) + 2
				print
		if not decoded:
			return False
	return True
	
card.info('jcoptool v0.1d')
if Help or len(args) < 1:
	print '\nUsage:\n\n\t%s [OPTIONS] <COMMAND> [ARGS] [ENC Key] [MAC Key] [KEK Key]' % sys.argv[0]
	print
	print '\tWhere COMMAND/ARGS are one of the following combinations:'
	print
	print "\tINFO\t\t\tDisplay useful info about the JCOP card and it's contents."
	print
	print '\tDES keys ENC MAC and KEK are always the final 3 arguments, and should be in HEX.'
	print '\tIf not specified, the default \'404142434445464748494A4B4C4D4E4F\' will be used.'
	print
	os._exit(True)

command= args[0]

if card.select():
	print
	print '    Card ID: ' + card.uid
	if card.readertype == card.READER_PCSC:
		print '    ATS: %s (%s)' % (card.pcsc_ats,card.ReadablePrint(card.ToBinary(card.pcsc_ats)))
else:
	print '    No RFID card present'
	print
	#os._exit(True)

#print '    ATR: ' + card.pcsc_atr
#print

# high speed select required for ACG
if not card.hsselect('08'):
	print '    Could not select RFID card for APDU processing'
	#os._exit(True)

print
print '    JCOP Identity Data:',
# send pseudo file select command for JCOP IDENTIFY
card.iso_7816_select_file(card.AID_JCOP_IDENTIFY,'04','00')
if card.errorcode == '6A82' and len(card.data) > 0:
	print card.data
	print
	decode_jcop_identify(card.data,'      ')
else:
	print '      Device does not support JCOP IDENTIFY!'

# card life cycle data
# high speed select required for ACG
if not card.hsselect('08'):
	print '    Could not select RFID card for APDU processing'
print
print '    Life Cycle data:',
if not card.gp_get_data('9F7F'):
	print " Failed - ", card.ISO7816ErrorCodes[card.errorcode]
else:
	print card.data
	if card.data[0:4] == '9F7F':
		decode_jcop_lifecycle(card.data[6:],'      ')

# select JCOP Card Manager
# high speed select required for ACG
if not card.hsselect('08'):
	print '    Could not select RFID card for APDU processing'
if not card.iso_7816_select_file(card.AID_CARD_MANAGER,'04','00'):
	print
	print "  Can't select Card Manager!",
	card.iso_7816_fail(card.errorcode)

if command == 'INFO':
	# high speed select required for ACG
	if not card.hsselect('08'):
		print '    Could not select RFID card for APDU processing'
	# get Card Recognition Data
	if not card.gp_get_data('0066'):
		print
		print "  Can't get Card Recognition Data!",
		card.iso_7816_fail(card.errorcode)
	pointer= 0
	item= card.data[pointer:pointer+2]
	if item != '66':
		print 'Unrecognised template:', item
		os._exit(True)
	pointer += 2
	item= card.data[pointer:pointer+2]
	length= int(item,16)

	print
	print '    Card Data length:',length
	pointer += 2
	item= card.data[pointer:pointer+2]
	if item != '73':
		print 'Unrecognised template:', item
		os._exit(True)
	pointer += 2
	item= card.data[pointer:pointer+2]
	length= int(item,16)
	print '      Card Recognition Data length:',length
	pointer += 2
	while pointer < len(card.data):
		item= card.data[pointer:pointer+2]
		try:
			print '        '+tags[item]+':',
			pointer += 2
			length= int(card.data[pointer:pointer + 2],16)
			pointer += 2
			if tags[item] == 'OID':
				decodedOID, dummy= decoder.decode(card.ToBinary(item+('%02x' % length)+card.data[pointer:pointer + length * 2]))
				print decodedOID.prettyPrint()
			else:
				if(card.data[pointer:pointer + 2]) == '06':
					decodedOID, dummy= decoder.decode(card.ToBinary(card.data[pointer:pointer + length * 2]))
					print
					print '          OID:', decodedOID.prettyPrint()
				else:
					print card.data[pointer:pointer + length * 2]
			pointer += length * 2
		except:
			print 'Unrecognised tag', item
			os._exit(True)
	# set up DES keys for encryption operations
	if len(args) > 1:
		enc_key= args[1]
		if len(args) > 2:
			mac_key= args[2]
	else:
		enc_key= card.GP_ENC_KEY
		mac_key= card.GP_MAC_KEY

if command == 'INSTALL':
	if len(args) > 2:
		enc_key= args[2]
		if len(args) > 3:
			mac_key= args[3]
	else:
		enc_key= card.GP_ENC_KEY
		mac_key= card.GP_MAC_KEY

if command == 'INFO' or command == 'INSTALL':
	# authenticate to card
	# initialise secure channel
	print
	print '      *** Warning'
	print '      *** Repeated authentication failures may permanently disable device'
	print
	x= string.upper(raw_input('      Attempt to authenticate (y/n)? '))
	if not x == 'Y':
		os._exit(True)

	# high speed select required for ACG
	if not card.hsselect('08'):
		print '    Could not select RFID card for APDU processing'
	host_challenge= card.GetRandom(8)
	if not card.gp_initialize_update(host_challenge):
		print 'Can\'t Initialise Update!'
		card.iso_7816_fail(card.errorcode)	
	card_key_diversification, card_key_info, card_sc_sequence_counter,card_challenge,card_cryptogram= card.gp_initialize_update_response_scp02(card.data)


	secure_channel_protocol= card_key_info[2:4]

	if secure_channel_protocol == card.GP_SCP02:
		# create ENC session key by encrypting derivation data with ENC key
		session_pad= '000000000000000000000000'
		derivation_data= '0182' + card_sc_sequence_counter + session_pad
		# create encryption object with ENC key
		e_enc= DES3.new(card.ToBinary(enc_key),DES3.MODE_CBC,card.DES_IV)
		enc_s_key= e_enc.encrypt(card.ToBinary(derivation_data))
		# data for cryptograms
		card_cryptogram_source= host_challenge + card_sc_sequence_counter + card_challenge
		host_cryptogram_source= card_sc_sequence_counter + card_challenge + host_challenge
		# check card cryptogram 
		check_cryptogram= string.upper(card.ToHex(card.DES3MAC(card.ToBinary(card_cryptogram_source), enc_s_key, '')))
		if not check_cryptogram == card_cryptogram:
			print 'Key mismatch!'
			print 'Card Cryptogram:      ', card_cryptogram
			print 'Calculated Cryptogram:', check_cryptogram
			os._exit(True)

		# cryptogram checks out, so we can use session key
		# create encryption object with ENC Session key
		s_enc= DES3.new(enc_s_key,DES3.MODE_CBC,card.DES_IV)

		# authenticate to card
		host_cryptogram= card.DES3MAC(card.ToBinary(host_cryptogram_source), enc_s_key, '')
		# create encryption object with MAC key
		e_enc= DES3.new(card.ToBinary(mac_key),DES3.MODE_CBC,card.DES_IV)
		# create C-MAC session key
		derivation_data= '0101' + card_sc_sequence_counter + session_pad
		cmac_s_key= e_enc.encrypt(card.ToBinary(derivation_data))
		if not card.gp_external_authenticate(host_cryptogram,cmac_s_key):
			print 'Card Authentication failed!'
			card.iso_7816_fail(card.errorcode)	
	else:
		print 'Unsupported Secure Channel Protocol:', secure_channel_protocol
		os._exit(True)


print '      Authentication succeeded'	
# get card status (list card contents)
# high speed select required for ACG
#if not card.hsselect('08'):
#		print '    Could not select RFID card for APDU processing'
print
print '    Card contents:'
for filter in '80','40','20','10':
	if not card.gp_get_status(filter,'02',''):
		if not card.errorcode == '6A88':
			print
			print "  Can't get Card Status!",
			card.iso_7816_fail(card.errorcode)
	print
	print '     ', card_status[filter]+':'
	if card.errorcode == '6A88':
		print '        None!'
	else:
		if not decode_gp_registry_data(card.data,'       ',filter):
			print '  Can\'t decode Registry!'
			print card.data
			os._exit(True)
os._exit(False)
