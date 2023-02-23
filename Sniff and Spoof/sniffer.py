#!/usr/bin/python3
from scapy.all import *

def print_pkt(pkt):
    pkt.show()

interfaces = ['br-60049e293b27']
print("* Start sniffing packets")
# Task1.1B Capture onlt the ICMP packet
# pkt = sniff(iface=interfaces, filter='icmp', prn=print_pkt)
# Task1.1B Capture any TCP packet that comes from a particular IP and with a destination port number 23
# Refers to the BPF reference guide
# The port number 23 is for telnet protocol
# pkt = sniff(iface=interfaces, filter='tcp && src host 10.9.0.5 && dst port 23', prn=print_pkt)
# Task1.1B Capture packets comes from or to go to a particular subnet. (Shouldn't pick that your VM is attached to.)
pkt = sniff(iface=interfaces , filter='net 128.230.0.0/16 ' , prn=print_pkt)
