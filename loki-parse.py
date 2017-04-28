#!/usr/bin/python
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from collections import defaultdict
from cStringIO import StringIO
from struct import unpack
import re
import json
from datetime import datetime
import argparse
import os
import sys
from aplib import Decompress

packet_queue = defaultdict(list)

def isCompletedSession(packet):
	packet_key_name = '%s:%s --> %s' % (packet[IP].src,packet[IP].sport, packet[IP].dst)
        packet_queue[packet_key_name].append(packet)

        for session in packet_queue:
                SYN     = False
                PSH_ACK = False
                ACK_FIN = False
		PSH_ACK_FIN = False

                for session_packet in packet_queue[session]:
                        if session_packet[TCP].flags == 2:
                                #print 'SYN found'
                                SYN = True
                        if session_packet[TCP].flags == 24:
                                #print 'PSH_ACK found'
                                PSH_ACK = True
                        if session_packet[TCP].flags == 17:
                                #print 'ACK_FIN found'
                                ACK_FIN = True
			if session_packet[TCP].flags == 25:
				#print 'PSH_ACK_FIN found'
				PSH_ACK_FIN = True

                if (SYN and PSH_ACK and ACK_FIN) or PSH_ACK_FIN:
			return True
	return False

def isLokiBotTraffic(http_headers):
	indicator_count = 0
	content_key_pattern = re.compile("^([A-Z0-9]{8}$)")

	if 'User-Agent' in http_headers and http_headers['User-Agent'] == 'Mozilla/4.08 (Charon; Inferno)':
		return True

	if 'HTTP-Method' in http_headers and http_headers['HTTP-Method'] == 'POST':
		indicator_count += 1

	if all(key in http_headers for key in ('User-Agent','Host','Accept','Content-Type','Content-Encoding', 'Content-Key')):
		indicator_count +=1

	if 'User-Agent' in http_headers and any(UAS_String in http_headers['User-Agent'] for UAS_String in ('Charon','Inferno')):
		indicator_count +=1

	if 'Content-Key' in http_headers and content_key_pattern.match(http_headers['Content-Key']):
		indicator_count +=1

	if indicator_count >= 3:
		return True
	else:
		return False


def parse_standard_payload(lb_payload):
	lb = {}
	ID = unpack("h", lb_payload.read(2))[0]
	lb_bot_id_strlen = unpack("i", lb_payload.read(4))[0]
	lb['Bot ID (%d)' % ID] = ''.join(unpack("s"*lb_bot_id_strlen, lb_payload.read(lb_bot_id_strlen)))

	ID = unpack("h", lb_payload.read(2))[0]
	lb_username_len = unpack("i", lb_payload.read(4))[0]
	lb['User Name (%d)' % ID] = ''.join(map(chr,unpack("h"*(lb_username_len/2), lb_payload.read(lb_username_len))))
	
	ID = unpack("h", lb_payload.read(2))[0]
	lb_hostname_len = unpack("i", lb_payload.read(4))[0]
        lb['Hostname (%d)' % ID] = ''.join(map(chr,unpack("h"*(lb_hostname_len/2), lb_payload.read(lb_hostname_len))))

	ID = unpack("h", lb_payload.read(2))[0]
        lb_domainhostname_len = unpack("i", lb_payload.read(4))[0]
        lb['Domain Hostname (%d)' % ID] = ''.join(map(chr,unpack("h"*(lb_domainhostname_len/2), lb_payload.read(lb_domainhostname_len))))

	screen_width = unpack("i", lb_payload.read(4))[0]
	screen_heigth = unpack("i", lb_payload.read(4))[0]

	lb['Screen Resolution'] = '%sx%s' % (screen_width, screen_heigth)


	isLocalAdmin = unpack("h", lb_payload.read(2))[0]
	if isLocalAdmin == 1:
		lb['Local Admin'] = True
	else:
		lb['Local Admin'] = Galse

	isBuiltInAdmin = unpack("h", lb_payload.read(2))[0]

	if isBuiltInAdmin == 1:
		lb['Built-In Admin'] = True
	else:
		lb['Built-In Admin'] = False

	is64bitOS = unpack("h", lb_payload.read(2))[0]

	if is64bitOS == 1:
		lb['64bit OS'] = True
	else:
		lb['64bit OS'] = False

	OS_Major = unpack("h", lb_payload.read(2))[0]
	OS_Minor = unpack("h", lb_payload.read(2))[0]
	OS_ProductType = unpack("h", lb_payload.read(2))[0]
	OS_Bug = unpack("h", lb_payload.read(2))[0]

	lb['Operating System'] = getOSVersion(OS_Major, OS_Minor, OS_ProductType)
	
	return lb, lb_payload
	
def parse_type27(lb_payload):
	
	lb, lb_payload = parse_standard_payload(lb_payload)

	reported = unpack("h", lb_payload.read(2))[0]

	if reported == 1:
		lb['First Transmission'] = False
	else:
		lb['First Transmission'] = True

	compressed = unpack("h", lb_payload.read(2))[0]

	if compressed == 1:
		lb['Data Compressed'] = True
	else:
		lb['Data Compressed'] = False

	placeholder1 = unpack("h", lb_payload.read(2))[0]
	placeholder2 = unpack("h", lb_payload.read(2))[0]
	placeholder3 = unpack("h", lb_payload.read(2))[0]

	lb['Original Application/Credential Data Size (Bytes)'] = unpack("i", lb_payload.read(4))[0]

	ID = unpack("h", lb_payload.read(2))[0]
	mutex_strlen = unpack("i", lb_payload.read(4))[0]
	mutex = ''.join(map(chr,unpack("h"*(mutex_strlen/2), lb_payload.read(mutex_strlen))))
	lb['Mutex (%d)' % ID] = mutex
	lb['Hidden File [Malware Exe]'] = '%%APPDATA%%\%s\%s.exe' % ( mutex[7:13], mutex[12:18])
	lb['Hidden File [Hash Database]'] = '%%APPDATA%%\%s\%s.hdb' % ( mutex[7:13], mutex[12:18])
	lb['Hidden File [Keylogger Database]'] = '%%APPDATA%%\%s\%s.kdb' % ( mutex[7:13], mutex[12:18])
	lb['Hidden File [Lock File]'] = '%%APPDATA%%\%s\%s.lck' % ( mutex[7:13], mutex[12:18])
	
	unique_key_len = unpack("i", lb_payload.read(4))[0]
	lb['Unique Key'] = ''.join(unpack("s"*unique_key_len, lb_payload.read(unique_key_len)))
	
	compressed_data_size = unpack("i", lb_payload.read(4))[0]
	lb['Compressed Application/Credential Data Size (Bytes)'] = compressed_data_size
	
	if lb['Data Compressed'] and lb['Compressed Application/Credential Data Size (Bytes)'] > 0:
		
		#print "Compressed Data Size: %s" % compressed_data_size
		compressed_data = bytearray(lb_payload.read(compressed_data_size))
		try:
			decompressed_data = Decompress(compressed_data).do()
			print decompressed_data
		except IndexError:
			lb['Decompressed Application/Credential Data'] = 'ERROR: Incomplete Packet Detected'
	return lb

	
def process_decompressed_app_data(decompressed_app_data):
	app_dict = {}
	data_stream = StringIO(decompressed_app_data)
	application = getApplicationFromID(unpack("i", data_stream.read(4))[0])
	app_dict[application]={}
	app_dict[application]['Unknown Value'] = unpack("i", data_stream.read(4))[0]
	application_bytes = unpack("i", data_stream.read(4))[0]
	application_data = data_stream.read(application_bytes)
	byte_count = 0
	#while byte_count <= application_bytes:
	#	pass
	return {'None': 'None'}

def parse_type28(lb_payload):
	lb, lb_payload = parse_standard_payload(lb_payload)
	
	ID = unpack("h", lb_payload.read(2))[0]
	mutex_strlen = unpack("i", lb_payload.read(4))[0]
	lb['Mutex (%d)' % ID] = ''.join(map(chr,unpack("h"*(mutex_strlen/2), lb_payload.read(mutex_strlen))))
	
	return lb
	

def parse_type2b(lb_payload):
	lb = {}
	lb['Unknown Hardcoded Value #1'] = unpack("h", lb_payload.read(2))[0]
	lb['Unknown Hardcoded Value #2'] = unpack("h", lb_payload.read(2))[0]
	lb['Unknown Hardcoded Value #3'] = unpack("h", lb_payload.read(2))[0]
	lb['Unknown Hardcoded Value #4'] = unpack("h", lb_payload.read(2))[0]
	
	lb['Original Keylogger Data Size'] = unpack("i", lb_payload.read(4))[0]
	
	ID = unpack("h", lb_payload.read(2))[0]
	mutex_strlen = unpack("i", lb_payload.read(4))[0]
	lb['Mutex (%d)' % ID] = ''.join(map(chr,unpack("h"*(mutex_strlen/2), lb_payload.read(mutex_strlen))))
	
	unique_key_len = unpack("i", lb_payload.read(4))[0]
	lb['Unique Key'] = ''.join(unpack("s"*unique_key_len, lb_payload.read(unique_key_len)))
	
	compressed_data_size = unpack("i", lb_payload.read(4))[0]
	lb['Compressed Keylogger Data Size (Bytes)'] = compressed_data_size
	compressed_keylogger_data = bytearray(lb_payload.read(compressed_data_size))

	try:
		decompressed_keylogger_data = Decompress(compressed_keylogger_data).do()
		print decompressed_keylogger_data
	except IndexError:
		lb['Decompressed Application/Credential Data'] = 'ERROR: Incomplete Packet Detected'
	
	return lb
	
def format_header(unformatted_http_header):
	http_header_dict = {}
	split_http_header = unformatted_http_header.split('\r\n')

	if split_http_header[0].startswith('POST '):
		method, URI, HTTPVersion = split_http_header.pop(0).split(' ')

	http_header_dict['HTTP-Method'] = method
	http_header_dict['HTTP-URI'] = URI
	http_header_dict['HTTP-Version'] = HTTPVersion

	for header in split_http_header:
		if ":" in header:
			key, value = header.split(': ',1)
			http_header_dict[key] = value

	return http_header_dict	

def extractHeaderAndPayload(full_session):
	http_header = {}
	http_payload = StringIO()
	
	for packet in full_session:
		if packet[TCP].flags in (24,25) :
			#print 'IP header says the packet is %s but the actual load is %s' % ((packet[IP].len - 40), len(packet[TCP].load))
			if packet[TCP].load.startswith('POST '):
				#packet.show()
				http_header = format_header(packet[TCP].load)
			else:
				#packet.show()
				if Padding in packet:
					http_payload = StringIO(packet[TCP].load + packet[Padding].load)
				else:
					http_payload = StringIO(packet[TCP].load)
	return http_header,http_payload		

def getApplicationFromID(id):
	app_dict = {}
	app_dict[1] = 'Mozilla Firefox'
	app_dict[2] = 'K-Meleon'
	app_dict[3] = 'Flock'
	app_dict[4] = 'Comodo IceDragon'
	app_dict[5] = 'SeaMonkey'
	app_dict[6] = 'Opera (OLD)'
	app_dict[7] = 'Apple Safari'
	app_dict[8] = 'Internet Explorer'
	app_dict[9] = 'Opera (NEW)'
	app_dict[10] = 'Comodo Dragon'
	app_dict[11] = 'CoolNovo'
	app_dict[12] = 'Google Chrome'
	app_dict[13] = 'Rambler Nichrome'
	app_dict[14] = 'RockMelt'
	app_dict[15] = 'Baidu Spark'
	app_dict[16] = 'Chromium'
	app_dict[17] = 'Titan Browser'
	app_dict[18] = 'Torch Browser'
	app_dict[19] = 'Yandex.Browser'
	app_dict[20] = 'Epic Privacy'
	app_dict[21] = 'CocCoc Browser'
	app_dict[22] = 'Vivaldi'
	app_dict[23] = 'Chromodo'
	app_dict[24] = 'Superbird'
	app_dict[25] = 'Coowon'
	app_dict[26] = 'Total Commander'
	app_dict[27] = 'FlashFXP'
	app_dict[28] = 'FileZilla'
	app_dict[29] = 'PuTTY/KiTTY'
	app_dict[30] = 'FAR Manager'
	app_dict[31] = 'SuperPutty'
	app_dict[32] = 'CyberDuck'
	app_dict[33] = 'Mozilla Thunderbird'
	app_dict[34] = 'Pidgin'
	app_dict[35] = 'Bitvise'
	app_dict[36] = 'NovaFTP'
	app_dict[37] = 'NetDrive'
	app_dict[38] = 'NppFTP'
	app_dict[39] = 'FTPShell'
	app_dict[40] = 'sherrodFTP'
	app_dict[41] = 'MyFTP'
	app_dict[42] = 'FTPBox'
	app_dict[43] = 'FtpInfo'
	app_dict[44] = 'Lines FTP'
	app_dict[45] = 'FullSync'
	app_dict[46] = 'Nexus File'
	app_dict[47] = 'JaSFtp'
	app_dict[48] = 'FTP Now'
	app_dict[49] = 'Xftp'
	app_dict[50] = 'Easy FTP'
	app_dict[51] = 'GoFTP'
	app_dict[52] = 'NETFile'
	app_dict[53] = 'Blaze Ftp'
	app_dict[54] = 'Staff-FTP'
	app_dict[55] = 'DeluxeFTP'
	app_dict[56] = 'ALFTP'
	app_dict[57] = 'FTPGetter'
	app_dict[58] = 'WS_FTP'
	app_dict[59] = 'Full Tilt Poker'
	app_dict[60] = 'PokerStars'
	app_dict[61] = 'AbleFTP'
	app_dict[62] = 'Automize'
	app_dict[63] = 'SFTP Net Drive'
	app_dict[64] = 'Anyclient'
	app_dict[65] = 'ExpanDrive'
	app_dict[66] = 'Steed'
	app_dict[67] = 'RealVNC/TightVNC'
	app_dict[68] = 'mSecure Wallet'
	app_dict[69] = 'Syncovery'
	app_dict[70] = 'SmartFTP'
	app_dict[71] = 'FreshFTP'
	app_dict[72] = 'BitKinex'
	app_dict[73] = 'UltraFXP'
	app_dict[74] = 'FTP Rush'
	app_dict[75] = 'Vandyk SecureFX'
	app_dict[76] = 'Odin Secure FTP Expert'
	app_dict[77] = 'Fling'
	app_dict[78] = 'ClassicFTP'
	app_dict[79] = 'NETGATE BlackHawk'
	app_dict[80] = 'Lunascape'
	app_dict[81] = 'QTWeb Browser'
	app_dict[82] = 'QupZilla'
	app_dict[83] = 'Maxthon'
	app_dict[84] = 'Foxmail'
	app_dict[85] = 'Pocomail'
	app_dict[86] = 'IncrediMail'
	app_dict[87] = 'WinSCP'
	app_dict[88] = 'Gmail Notifier Pro'
	app_dict[89] = 'CheckMail'
	app_dict[90] = 'SNetz Mailer'
	app_dict[91] = 'Opera Mail'
	app_dict[92] = 'Postbox'
	app_dict[93] = 'Cyberfox'
	app_dict[94] = 'Pale Moon'
	app_dict[95] = 'FossaMail'
	app_dict[96] = 'Becky!'
	app_dict[97] = 'MailSpeaker'
	app_dict[98] = 'Outlook'
	app_dict[99] = 'yMail'
	app_dict[100] = 'Trojita'
	app_dict[101] = 'TrulyMail'
	app_dict[102] = 'StickyPad'
	app_dict[103] = 'To-Do Desklist'
	app_dict[104] = 'Stickies'
	app_dict[105] = 'NoteFly'
	app_dict[106] = 'NoteZilla'
	app_dict[107] = 'Sticky Notes'
	app_dict[108] = 'WinFtp'
	app_dict[109] = '32BitFTP'
	app_dict[110] = 'Mustang Browser'
	app_dict[111] = '360 Browser'
	app_dict[112] = 'Citrio Browser'
	app_dict[113] = 'Chrome SxS'
	app_dict[114] = 'Orbitum'
	app_dict[115] = 'Sleipnir'
	app_dict[116] = 'Iridium'
	app_dict[117] = '117'
	app_dict[118] = '118'
	app_dict[119] = '119'
	app_dict[120] = '120'
	app_dict[121] = 'Windows Credentials'
	app_dict[122] = 'FTP Navigator'
	app_dict[123] = 'Windows Key'
	app_dict[124] = 'KeePass'
	app_dict[125] = 'EnPass'
	app_dict[126] = 'Waterfox'
	app_dict[127] = 'AI RoboForm'
	app_dict[128] = '1Password'
	app_dict[129] = 'Mikrotik WinBox'
	
	return app_dict[id]
	
	
	
def getOSVersion(major, minor, product_type):
	ms_OS_dict = {}
	ms_OS_dict['10.0.1'] = 'Windows 10 Workstation'
	ms_OS_dict['10.0.2'] = 'Windows Server 2016 Domain Controller'
	ms_OS_dict['10.0.3'] = 'Windows Server 2016'
	ms_OS_dict['6.3.1'] = 'Windows 8.1 Workstation'
	ms_OS_dict['6.3.3'] = 'Windows Server 2012 R2'
	ms_OS_dict['6.3.2'] = 'Windows Server 2012 R2 Domain Controller'
	ms_OS_dict['6.2.1'] = 'Windows 8 Workstation'
	ms_OS_dict['6.2.2'] = 'Windows Server 2012 Domain Controller'
	ms_OS_dict['6.2.3'] = 'Windows Server 2012'
	ms_OS_dict['6.1.1'] = 'Windows 7 Workstation'
	ms_OS_dict['6.1.2'] = 'Windows Server 2008 R2 Domain Controller'
	ms_OS_dict['6.1.3'] = 'Windows Server 2008 R2'
	ms_OS_dict['6.0.1'] = 'Windows Vista Workstation'
	ms_OS_dict['6.0.2'] = 'Windows Server 2008 Domain Controller'
	ms_OS_dict['6.0.3'] = 'Windows Server 2008'
	ms_OS_dict['5.2.1'] = 'Windows XP 64-Bit Edition'
	ms_OS_dict['5.2.2'] = 'Windows Server 2003 Domain Controller'
	ms_OS_dict['5.2.3'] = 'Windows Server 2003'
	ms_OS_dict['5.1.1'] = 'Windows XP Workstation'
	return ms_OS_dict['%s.%s.%s' % (major, minor, product_type)]


def parse_lokibot_payload(lb_payload):
	lb = {}

	lb['Version'] = float(unpack("h", lb_payload.read(2))[0])/10
	lb_payload_type = unpack("h", lb_payload.read(2))[0]
	if lb_payload_type == 0x27:
		#print "Application/Credential payload detected"
		lb['Payload Type'] = "Application/Credential Data"
		lb.update(parse_type27(lb_payload))
	elif lb_payload_type == 0x28:
		lb['Payload Type'] = "C2 Request"
		lb.update(parse_type28(lb_payload))
	elif lb_payload_type == 0x2b:
		lb['Payload Type'] = "Keylogger Data"
		lb.update(parse_type2b(lb_payload))
	return lb
	

def print_to_file(lb_json_output):
	filename =''
	type = ''
	app=''
	c2_server = lb_json_output['Packet Info - Destination IP']
	
	if lb_json_output['Payload Type'] == 'Application/Credential Data':
		type = 'AppCred'
	elif lb_json_output['Payload Type'] == 'Keylogger Data':
		type = 'KeyLogger'
	elif lb_json_output['Payload Type'] == 'C2 Request':
		type = 'C2Request'
	
	filename = '%s-%s%s.txt' % (c2_server, type, app)
	#print filename
	
	
def process_packets(packet):
	packet_key_name = '%s:%s --> %s' % (packet[IP].src,packet[IP].sport, packet[IP].dst)
	if isCompletedSession(packet):
                http_header, http_payload = extractHeaderAndPayload(packet_queue[packet_key_name])
		#print "header and payload extracted"
		if isLokiBotTraffic(http_header):
			#print "Loki-Bot packet detected"
			parsed_payload={}
			parsed_payload['Packet Info - Source IP'] = packet[IP].src
			parsed_payload['Packet Info - Source Port'] = packet[IP].sport
			parsed_payload['Packet Info - Destination IP'] = packet[IP].dst
			parsed_payload['Packet Info - Destination Port'] = packet[IP].dport
			parsed_payload['Packet Info - Data Transmission Time'] = datetime.fromtimestamp(packet.time).isoformat()
			parsed_payload.update(parse_lokibot_payload(http_payload))
			print json.dumps(parsed_payload,ensure_ascii=False,sort_keys=True, indent=4)
			#print_to_file(parsed_payload)
                del packet_queue[packet_key_name]


parser = argparse.ArgumentParser(description='This script can parse Loki-Bot related network communications from a compromised host to the C2 server. The output is the decoded contents of this network communications.')
parser.add_argument('--pcap', help='Path and filename of the pcap file that you would like to parse. If this switch is not specified, this script will default to sniffing the wire.')
#parser.add_argument('--output', help='Path of where to save the output to. If this switch is not specified, this script will default to printing Loki-Bot associated metadata')

args = parser.parse_args()

#if not os.path.isdir(args.output):
#	print "Error: The output directory you provided (%s) does not exist" % args.output
#	sys.exit(-1)


if args.pcap:
	if not os.path.isfile(args.pcap):
		print "Error: The PCAP file you provided (%s) could not be found" % args.pcap
		sys.exit(-1)
	print "Reading PCAP file"
	packets = rdpcap(args.pcap)
	#print "PCAP Read"
	for packet in packets:
		if TCP in packet:
			process_packets(packet)
else:
	print "Sniffing PCAPS from the wire"
	sniff(iface='eth0', filter='tcp', prn=process_packets)
