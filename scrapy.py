import psutil
import socket
import re
from scapy.all import ARP, Ether, sniff
from collections import defaultdict
from urllib.parse import urlparse
import concurrent.futures
import subprocess
import webbrowser

# Install required packages
try:
    import psutil
except ImportError:
    subprocess.check_call(["pip", "install", "psutil"])

try:
    from scapy.all import ARP, Ether, sniff
except ImportError:
    subprocess.check_call(["pip", "install", "scapy"])

try:
    import concurrent.futures
except ImportError:
    subprocess.check_call(["pip", "install", "futures"])

try:
    import webbrowser
except ImportError:
    subprocess.check_call(["pip", "install", "webbrowser"])

# Global variables
selected_interface = None
captured_packets = []

# Egy-Scrap Logo and Colors
logo = r"""
 ________  ________   ________   ________     
|\   __  \|\   ___  \|\   ___  \|\   __  \    
\ \  \|\  \ \  \\ \  \ \  \\ \  \ \  \|\  \   
 \ \   ____\ \  \\ \  \ \  \\ \  \ \  \\\  \  
  \ \  \___|\ \  \\ \  \ \  \\ \  \ \  \\\  \ 
   \ \__\    \ \__\\ \__\ \__\\ \__\ \_______\
    \|__|     \|__| \|__|\|__| \|__|\|_______|
"""

COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_CYAN = "\033[96m"
COLOR_END = "\033[0m"

# Helper function to print colored text
def print_colored(text, color):
    print(color + text + COLOR_END)


def get_available_interfaces():
    interfaces = []

    # Method 1: Get network interfaces using psutil
    for interface in psutil.net_if_addrs().keys():
        if not is_interface_loopback(interface):
            interfaces.append(interface)

    # Method 2: Get network interfaces using netifaces
    try:
        import netifaces
        interfaces = netifaces.interfaces()
    except ImportError:
        pass

    # Method 3: Get network interfaces using subprocess
    if not interfaces:
        try:
            result = subprocess.check_output(["ip", "link", "show"], universal_newlines=True)
            interfaces = re.findall(r"\d+: (\w+):", result)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass

    return interfaces


def is_interface_loopback(interface):
    try:
        addresses = psutil.net_if_addrs()[interface]
        for address in addresses:
            if address.family == socket.AF_INET and address.address == '127.0.0.1':
                return True
    except (KeyError, AttributeError):
        return False
    return False


def discover_devices_on_network(interface):
    # Method 1: Sniff ARP packets
    devices = []
    try:
        devices = discover_devices_by_sniff(interface)
    except Exception as e:
        print("An error occurred while executing 'discover_devices_by_sniff': {}".format(str(e)))

    # Method 2: Scan IP addresses
    if not devices:
        try:
            devices = discover_devices_by_scan(interface)
        except Exception as e:
            print("An error occurred while executing 'discover_devices_by_scan': {}".format(str(e)))

    # Method 3: Reverse DNS lookup
    if not devices:
        try:
            devices = discover_devices_by_dns(interface)
        except Exception as e:
            print("An error occurred while executing 'discover_devices_by_dns': {}".format(str(e)))

    return devices


def discover_devices_by_sniff(interface):
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.0/24")
    result = sniff(iface=interface, filter="arp", timeout=3, count=0)
    devices = []
    for packet in result:
        if ARP in packet and packet[ARP].op in (1, 2):  # Who-has or is-at
            devices.append({'ip': packet[ARP].psrc, 'mac': packet[ARP].hwsrc, 'name': ''})
    return devices


def discover_devices_by_scan(interface):
    # Method 4: Scan IP addresses
    # Perform IP address scanning here and return the discovered devices
    return []


def discover_devices_by_dns(interface):
    # Method 5: Reverse DNS lookup
    # Perform reverse DNS lookup and return the discovered devices
    return []


def display_devices(devices):
    print_colored("Devices on the network:", COLOR_CYAN)
    print("-----------------------")
    for device in devices:
        print("IP: {} | MAC: {} | Name: {}".format(device['ip'], device['mac'], device['name']))


def get_packet_details(packet):
    if packet.haslayer("IP"):
        protocol = "IP"
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
    elif packet.haslayer("IPv6"):
        protocol = "IPv6"
        src_ip = packet["IPv6"].src
        dst_ip = packet["IPv6"].dst
    else:
        protocol = ""
        src_ip = ""
        dst_ip = ""

    if packet.haslayer("TCP"):
        src_port = packet["TCP"].sport
        dst_port = packet["TCP"].dport
    elif packet.haslayer("UDP"):
        src_port = packet["UDP"].sport
        dst_port = packet["UDP"].dport
    else:
        src_port = ""
        dst_port = ""

    return protocol, src_ip, dst_ip, src_port, dst_port


def handle_packet(packet):
    captured_packets.append(packet)
    protocol, src_ip, dst_ip, src_port, dst_port = get_packet_details(packet)

    # Filter packets by HTTP/HTTPS requests only
    if (protocol == "IP" or protocol == "IPv6") and (
        (src_port == 80 or dst_port == 80) or (src_port == 443 or dst_port == 443)
    ):
        payload = str(packet.payload)

        # Filter packets by POST requests only
        if "POST" in payload:
            print_colored("Captured Packet:", COLOR_YELLOW)
            print("----------------")
            print("Protocol: {}".format(protocol))
            print("Source IP: {}".format(src_ip))
            print("Destination IP: {}".format(dst_ip))
            print("Source Port: {}".format(src_port))
            print("Destination Port: {}".format(dst_port))
            print("Payload:")
            print(payload)
            print()


def start_packet_capture(interface):
    print_colored("Starting packet capture on interface: {}".format(interface), COLOR_GREEN)
    sniff(iface=interface, prn=handle_packet)


def open_packet_url(packet):
    protocol, src_ip, dst_ip, src_port, dst_port = get_packet_details(packet)

    # Extract URL from packet payload
    payload = str(packet.payload)
    match = re.search(r"(?P<url>https?://[^\s]+)", payload)
    if match:
        url = match.group("url")
        parsed_url = urlparse(url)

        # Open the URL in a web browser
        print_colored("Opening URL: {}".format(url), COLOR_GREEN)
        webbrowser.open(url)


def process_user_input():
    global selected_interface

    while True:
        print_colored("1. Select network interface", COLOR_YELLOW)
        print_colored("2. Discover devices on the network", COLOR_YELLOW)
        print_colored("3. Display captured packets", COLOR_YELLOW)
        print_colored("4. Open captured packet URL", COLOR_YELLOW)
        print_colored("5. Start packet capture", COLOR_YELLOW)
        print_colored("6. Exit", COLOR_YELLOW)
        choice = input("Enter your choice: ")

        if choice == "1":
            interfaces = get_available_interfaces()
            print_colored("Available interfaces:", COLOR_CYAN)
            for i, interface in enumerate(interfaces):
                print("{}. {}".format(i + 1, interface))
            selection = int(input("Select an interface: "))
            selected_interface = interfaces[selection - 1]
            print_colored("Interface {} selected.".format(selected_interface), COLOR_GREEN)

        elif choice == "2":
            if selected_interface:
                devices = discover_devices_on_network(selected_interface)
                display_devices(devices)
            else:
                print_colored("No interface selected. Please select an interface first.", COLOR_RED)

        elif choice == "3":
            if captured_packets:
                for i, packet in enumerate(captured_packets):
                    print_colored("Packet {}".format(i + 1), COLOR_CYAN)
                    print("----------------")
                    print(packet.show())
                    print()
            else:
                print_colored("No captured packets.", COLOR_RED)

        elif choice == "4":
            if captured_packets:
                for i, packet in enumerate(captured_packets):
                    print_colored("Packet {}".format(i + 1), COLOR_CYAN)
                    print("----------------")
                    print(packet.show())
                    print()
                selection = int(input("Select a packet to open the URL: "))
                if 1 <= selection <= len(captured_packets):
                    packet = captured_packets[selection - 1]
                    open_packet_url(packet)
                else:
                    print_colored("Invalid selection.", COLOR_RED)
            else:
                print_colored("No captured packets.", COLOR_RED)

        elif choice == "5":
            if selected_interface:
                start_packet_capture(selected_interface)
            else:
                print_colored("No interface selected. Please select an interface first.", COLOR_RED)

        elif choice == "6":
            break

        else:
            print_colored("Invalid choice. Please try again.", COLOR_RED)


if __name__ == "__main__":
    print_colored(logo, COLOR_CYAN)
    process_user_input()
