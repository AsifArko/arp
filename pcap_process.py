from scapy.all import *

packets = rdpcap("arper.pcap")


f = open("processed_pcap.txt",'w')

for i in packets.sessions():
    f.write(i+'\n')
f.close()

for packet in packets:
    ip = packet.payload
    
    print "src_mac : {0} ".format(packet.src)
    print "dst_mac : {0} ".format(packet.dst)
    
    if ip.proto==17:

        udp = ip.payload
        print ("udp_sport : {0}".format(udp.sport))
        print ("udp_dport : {0}".format(udp.dport))
        
    if ip.proto==6:

        tcp = ip.payload
        print ("tcp_sport : {0}".format(tcp.sport))
        print ("tcp_dport : {0}".format(tcp.dport))


    if ip.proto==1:

        icmp = ip.payload
        print ("icmp_sport : {0}".format(icmp.sport))
        print ("icmp_dport : {0}".format(icmp.dport))

    print '\n'
    
