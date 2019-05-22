from scapy.all import *

packets = rdpcap("arper.pcap")


f = open("processed_pcap.txt",'w')

for packet in packets:
    ip = packet.payload
    
    if ip.proto==17:
        udp = ip.payload

        txt = "src_mac : {0} \tsrc_ip : {1} \t UDP \tUDP_SRC : {2}\n".format(packet.src,ip.src,udp.sport)
        print "src_mac : {0} \tsrc_ip : {1} \t UDP \tUDP_SRC : {2}".format(packet.src,ip.src,udp.sport)
        print "dst_mac : {0} \tdst_ip : {1} \t UDP \tUDP_DST :{2}".format(packet.dst,ip.dst,udp.dport)
        f.write(txt)
    
    if ip.proto==6:
        tcp = ip.payload

        txt = "src_mac : {0} \tsrc_ip : {1} \t TCP \tTCP_SRC : {2}\n".format(packet.src,ip.src,tcp.sport)

        print "src_mac : {0} \tsrc_ip : {1} \t TCP \tTCP_SRC : {2}".format(packet.src,ip.src,tcp.sport)
        print "dst_mac : {0} \tdst_ip : {1} \t TCP \tTCP_DST :{2}".format(packet.dst,ip.dst,tcp.dport)
        
        f.write(txt)

    if ip.proto==1:
        icmp = ip.payload

        txt = "src_mac : {0} \tsrc_ip : {1} \t ICMP \tUDP_SRC : {2}\n".format(packet.src,ip.src,icmp.sport)
    
        print "src_mac : {0} \tsrc_ip : {1} \t ICMP \tICMP_SRC : {2}".format(packet.src,ip.src,icmp.sport)
        print "dst_mac : {0} \tdst_ip : {1} \t ICMP \tICMP_DST :{2}".format(packet.dst,ip.dst,icmp.dport)

        f.write(txt)
    


f.close()
