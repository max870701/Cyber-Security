#!/usr/bin/python3
from scapy.all import *
import sys

# sr1() function only return one packet that answered the packet sent
def auto_hop(target):
    hop  = 0
    while hop >= 0:
        hop += 1
        a = IP(dst=target, ttl=hop)
        b = ICMP()
        packet = a / b
        ans = sr1(packet, timeout=1, iface='br-60049e293b27')
        if ans is None:
            continue
        elif ans.src == target:
            # Reached the destination
            print("Reached the destination: ", ans.src)
            print("We need %d Hops to reach %s" % (hop, ans.src))
            break
        else:
            print("%d Hops: " % hop, ans.src)

auto_hop(target=sys.argv[1])
