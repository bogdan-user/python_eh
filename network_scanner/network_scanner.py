
import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help = "Scan the network for the MAC addresses.")
    options = parser.parse_args()
    return options

def scan(ip):
    if not ip.target:
        print("Please enter a valid IP. Use --help for more information.")
    else:
        arp_request = scapy.ARP(pdst=ip.target)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        client_list = []
        for element in answered_list:
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            client_list.append(client_dict)
        return client_list

def print_scan(lst):
    if lst:
        print("IP\t\t\tMAC Address\n-----------------------------------------")
        for element in lst:
            print(element["ip"] + "\t\t" +  element["mac"])
    else:
        pass

args = get_arguments()
scan_result = scan(args)
print_scan(scan_result)
