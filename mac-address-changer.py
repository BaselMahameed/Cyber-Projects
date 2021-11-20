#!/use/bin/env python

import subprocess
import optparse
import re


def get_arguments():

    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="interface to change the mac address")
    parser.add_option("-m", "--mac", dest="new_mac", help="the new mac address")
    (options, arguments)= parser.parse_args()
    if not options.interface:
        parser.error("plaese specify an interface, use -h or --hlp for more info")
    elif not options.new_mac:
        parser.error("[-] please specify an new mac address, use -h or --help for more info")
    return options

def mac_change(interface, mac_address):
    print("[+]changing the MAC address for the interface " + interface + " to " + mac_address)

    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", mac_address])
    subprocess.call(["ifconfig", interface, "up"])

def get_current_mac(interface):
    ifconfig_results = subprocess.check_output(["ifconfig", interface])
    mac_address_search_results = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_results)
    if mac_address_search_results:
        return mac_address_search_results.group(0)
    else:
        print("[-] Could not MAC address")

options = get_arguments()
current_mac = get_current_mac(options.interface)
print("the MAC > " + str(current_mac))

mac_change(options.interface, options.new_mac)

current_mac = get_current_mac(options.interface)
if current_mac == options.new_mac:
    print("[+] MAC address was successfullu changed to " + current_mac)
else:
    print("[-] MAC address did not get changed")








