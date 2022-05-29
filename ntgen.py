from email.policy import HTTP
import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

if len(sys.argv)!=3:
    print('Usage: sudo python ntgen.py [nPackets] [onInterface]')
    sys.exit(-1)

nPackets= int(sys.argv[1])
onIface= str(sys.argv[2])

#TODO: loopback case must be fixed
#ip = get_if_addr(onIface)

for x in range(nPackets):
    #if ip=='127.0.0.1':
        #sendp(Loopback()/IP(src=RandIP(), dst=RandIP())/TCP, iface=onIface)
    sendp(IP(src=RandIP(), dst=RandIP()), iface=onIface)
