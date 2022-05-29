from email.policy import HTTP
import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

if len(sys.argv)!=4:
    print('Usage: sudo python ntgen.py [nPackets] [onInterface] [dstMAC]')
    print('-dstMAC is the destination MAC address. It is formatted as six sets of two digits or characters, separated by colons:')
    print(' e.g. 03:00:72:3a:14:32')
    sys.exit(-1)

nPackets = int(sys.argv[1])
onIface = str(sys.argv[2])
dstMAC = str(sys.argv[3])

#TODO: loopback case must be fixed
#ip = get_if_addr(onIface)
for x in range(nPackets):
    #if ip=='127.0.0.1':
        #sendp(Loopback()/IP(src=RandIP(), dst=RandIP())/TCP, iface=onIface)
    pkt=Ether(dst=dstMAC)/IP(src=RandIP()._fix(), dst=RandIP()._fix())/UDP()
    print(pkt[IP].src,'-->',pkt[IP].dst)
    sendp(pkt, iface=onIface, verbose=0)


