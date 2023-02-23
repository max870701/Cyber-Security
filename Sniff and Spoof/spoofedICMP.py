#!/usr/bin/python3
from scapy.all import *
# Host A: 10.9.0.5
# Host B: 10.9.0.6
a = IP(src='10.9.0.5', dst='10.9.0.6')
b = ICMP()
# Overloaded / operator
packet = a / b
send(packet)
