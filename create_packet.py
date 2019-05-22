from scapy.all import *

server = "www.google.com"

packet = Ether(src='00:00:00:11:11:11')
print ("Ethernet : {0}\n".format(repr(packet)))

ip = packet/IP(dst=server)
print ("IP : {0}".format(repr(ip)))

tcp = ip/TCP(dport=80)
print ("TCP : {0}".format(repr(tcp)))

http = Ether()/IP(dst=server)/TCP(dport=80)/"GET /index.html HTTP/1.0\r\n\r\n"
print ('HTTP-2 : {0}'.format(repr(http)))
