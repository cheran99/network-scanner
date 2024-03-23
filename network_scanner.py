from scapy.all import ARP, Ether, srp, TCP, IP
import argparse

def arp_scan(ip):
    arp_req_frame = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
    result = srp(arp_req_frame, timeout=3, verbose=False)[0]
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def port_scan(ip, ports):
    open_ports = []
    response, _ = srp(IP(dst=ip)/TCP(dport=ports, flags="S"), timeout=1, verbose=False)
    for sent_packet, received_packet in response:
        if received_packet.haslayer(TCP) and received_packet.getlayer(TCP).flags == 0x12:
            open_ports.append(received_packet.getlayer(TCP).sport)
    return open_ports

def parse_arguments():
    parser = argparse.ArgumentParser(description="Network Scanner")
    parser.add_argument("-t", "--target", dest="target", help="Target IP address")
    parser.add_argument("-p", "--ports", dest="ports", help="Port range to scan (e.g., '1-100')")
    args = parser.parse_args()
    if not args.target or not args.ports:
        parser.error("Please specify a target IP and ports to scan.")
    return args


def main():
    args = parse_arguments()
    target_ip = args.target
    ports = range(int(args.ports.split('-')[0]), int(args.ports.split('-')[1]) + 1)

    print(f"Scanning {target_ip} for open ports...")
    open_ports = port_scan(target_ip, ports)

    if open_ports:
        print("Open ports:")
        for port in open_ports:
            print(f" - Port {port} is open")
    else:
        print("No open ports found on the target.")

    print("Scanning network for devices...")
    devices = arp_scan(target_ip)
    print("Devices found:")
    for device in devices:
        print(f" - IP: {device['ip']}, MAC: {device['mac']}")

if __name__ == "__main__":
    main()
