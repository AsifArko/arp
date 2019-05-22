import os
from scapy.all import *

packets = rdpcap('arper.pcap')

dir_scalaton = '/home/hoods/Projects/scapy-tools/PacketsPDF/%s.eps'

for i in range(100):
    directory = dir_scalaton%i
    packets[i].pdfdump(directory,layer_shift=1)

    print "Successfully generated packet pdf [%s]"%i
