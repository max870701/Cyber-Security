#!/usr/bin/python3
from scapy.all import *
from ipaddress import IPv4Address
from random import getrandbits
# Host A: An arbitrary source
# Host B: 10.9.0.6
a = IP(src=str(IPv4Address(getrandbits(32))), dst='10.9.0.6')
b = ICMP()
# Overloaded / operator
packet = a / b
send(packet)