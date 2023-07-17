import nmap
import requests
from bs4 import BeautifulSoup
from scapy.all import sr1, IP, TCP

# Scan target IP address using Nmap
def port_scan(target_ip):
    scanner = nmap.PortScanner()
    result = scanner.scan(target_ip, arguments='-p1-65535 -T4 -A -v')

    open_ports = []

    for protocol in result['scan'][target_ip]:
        for port in result['scan'][target_ip][protocol]:
            state = result['scan'][target_ip][protocol][port]['state']
            if state == 'open':
                open_ports.append(port)

    return open_ports

# Perform a vulnerability scan on target IP using online vulnerability databases
def vulnerability_scan(target_ip):
    url = f'https://www.cvedetails.com/google-search-results.php?q={target_ip}&sa=Submit'
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')

    vulnerabilities = []
    vuln_table = soup.find('table', {'id': 'vulnslisttable'})

    if vuln_table:
        vuln_rows = vuln_table.find_all('tr')
        for row in vuln_rows[1:]:
            cols = row.find_all('td')
            if len(cols) >= 4:
                cve_id = cols[1].text.strip()
                severity = cols[3].text.strip()
                vulnerabilities.append((cve_id, severity))

    return vulnerabilities

# Send a TCP SYN packet to check if a specific port is open
def check_port(target_ip, port):
    packet = IP(dst=target_ip) / TCP(dport=port, flags="S")

    response = sr1(packet, timeout=1, verbose=0)
    if response and response.haslayer(TCP) and response[TCP].flags == "SA":
        return True

    return False

# Generate a report based on the scan results
def generate_report(target_ip, open_ports, vulnerabilities):
    print("Network Penetration Test Report")
    print("===============================")
    print(f"Target IP: {target_ip}\n")

    if open_ports:
        print("Open Ports:")
        for port in open_ports:
            print(f" - Port {port} is open")

    print()

    if vulnerabilities:
        print("Vulnerabilities:")
        for cve_id, severity in vulnerabilities:
            print(f" - CVE ID: {cve_id}, Severity: {severity}")

    if not open_ports and not vulnerabilities:
        print("No significant findings.")

# Main function
def main():
    target_ip = input("Enter the target IP address: ")

    print("\nPerforming port scan...")
    open_ports = port_scan(target_ip)
    if open_ports:
        print("Open ports found on the target IP address.")
    else:
        print("No open ports found on the target IP address.")

    print("\nPerforming vulnerability scan...")
    vulnerabilities = vulnerability_scan(target_ip)

    generate_report(target_ip, open_ports, vulnerabilities)

if __name__ == '__main__':
    main()
