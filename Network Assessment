import socket
from scapy.all import *

# Scan common ports on a target IP address
def port_scan(target_ip):
    common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445]

    open_ports = []

    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((target_ip, port))

        if result == 0:
            open_ports.append(port)

        sock.close()

    return open_ports

# Perform a vulnerability scan on a target IP address
def vulnerability_scan(target_ip):
    # Implement your vulnerability scanning logic here
    # This can include checking for known vulnerabilities in services running on the target IP address

    # Example: Checking if the target IP address is vulnerable to Heartbleed (CVE-2014-0160)
    result = sr1(IP(dst=target_ip)/TCP(dport=443)/TLS(), verbose=0)

    if result and result[TLS].version == 'TLS 1.0':
        print(f"Target IP: {target_ip} is vulnerable to Heartbleed (CVE-2014-0160)")

# Main function
def main():
    target_ip = input("Enter the target IP address: ")

    print("\nPerforming port scan...")
    open_ports = port_scan(target_ip)
    if open_ports:
        print("Open ports found on the target IP address:")
        for port in open_ports:
            print(f"Port {port} is open")
    else:
        print("No open ports found on the target IP address")

    print("\nPerforming vulnerability scan...")
    vulnerability_scan(target_ip)

if __name__ == '__main__':
    main()
