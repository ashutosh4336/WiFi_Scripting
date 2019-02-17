#!usr/bin/python

import socket
from scapy.all import *

hidden_ssid_aps = set()

def PacketHandler(pkt) :
	if pkt.haslayer(Dot11Beacon) :
		if not pkt.info :
			if pkt.addr3 not in hidden_ssid_aps :
				hidden_ssid_aps.add(pkt.addr3)
				print "Hidden SSID Network Found :) BSSID: ", pkt.addr3
		

	elif pkt.haslayer(Dot11ProbeResp) and (pkt.addr3 in hidden_ssid_aps) :
		print "Hidden SSID Uncovered ", pkt.info, pkt.addr3



sniff(iface = sys.argv[1], count = int(sys.argv[2]), prn = PacketHandler)

