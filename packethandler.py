#!usr/bin/python

import sys

from scapy.all import *

def PacketHandler(pkt) :

	if pkt.haslayer(Dot11) :	
		print pkt.summary()
	else:
	
		print "Not Dot11 Print"

sniff(iface = sys.argv[1], count = int(sys.argv[2]), prn = PacketHandler)
