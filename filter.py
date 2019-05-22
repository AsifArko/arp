from scapy.all import *

fil = str(raw_input("Input the filter : "))

packets = rdpcap('arper.pcap')
count = 1

for i in packets:
    if fil in repr(i):
        print count ,'\t' ,repr(i)
        print
        count+=1
