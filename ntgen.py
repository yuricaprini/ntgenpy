from email.policy import HTTP
import sys
import logging
import ipaddress
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

if len(sys.argv)!=5:
	print('Usage: sudo python ntgen.py [nPackets] [onInterface] [dstMAC] [pathToPcap]')
	print('-dstMAC is the destination MAC address. It is formatted as six sets of two digits or characters, separated by colons:')
	print(' e.g. 03:00:72:3a:14:32')
	sys.exit(-1)

nPackets = int(sys.argv[1])
onIface = str(sys.argv[2])
dstMAC = str(sys.argv[3])
pathToPcap = str(sys.argv[4])

#TODO: loopback case must be fixed
#ip = get_if_addr(onIface)
for x in range(nPackets):
	src_ip = ipaddress.ip_address(str(RandIP()._fix()))
	while src_ip.is_multicast or src_ip.is_private or src_ip.is_loopback or src_ip.is_link_local:
		src_ip = ipaddress.ip_address(str(RandIP()._fix()))

	
	dst_ip = ipaddress.ip_address(str(RandIP()._fix()))
	while dst_ip.is_multicast or dst_ip.is_private or dst_ip.is_loopback or dst_ip.is_link_local:
		dst_ip = ipaddress.ip_address(str(RandIP()._fix()))
	
	pkt=Ether(dst=dstMAC)/IP(src = format(src_ip), dst = format(dst_ip))/UDP()
	print(pkt[IP].src,'-->',pkt[IP].dst)
	wrpcap(pathToPcap, pkt, append=True)

