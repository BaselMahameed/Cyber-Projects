#!/use/bin/env python

import scapy.all as scapy
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP Range")
    options = parser.parse_args()
    if not options.target:
        parser.error("plaese specify an interface, use -h or --hlp for more info")
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip) #wich IP we will scan
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # the mac address
    arp_request_boradcast = broadcast/arp_request # generate the two functions
    answer_list= scapy.srp(arp_request_boradcast, timeout=1, verbose=False) [0] # sending and receving packets


    client_list=[]
    for elemnt in answer_list: # print each elemnt from the answer list
        client_dic={"IP":elemnt[1].psrc,"MAC":elemnt[1].hwsrc}
        client_list.append(client_dic)
        #print(elemnt[1].psrc +"\t\t"+ elemnt[1].hwsrc) # the IP and the Mac Address
    return client_list

def print_results(client_list):
    print("IP\t\t\tMac Address\n----------------------------------------------")

    for client in client_list:
        print(client["IP"] + "\t\t" + client["MAC"])



options = get_arguments()
scan_results = scan(options.target)
print_results(scan_results)





