import nmap

def deep_nmap_scan(ip):
    # Get more device info including OS detection and version info using nmap, and hostname
    # Initialize the Nmap PortScanner
    # Explicitly add typical Windows Nmap paths in case the environment PATH is missing it.
    nm = nmap.PortScanner(nmap_search_path=('nmap', '/usr/bin/nmap', '/usr/local/bin/nmap', r'C:\Program Files (x86)\Nmap\nmap.exe', r'C:\Program Files\Nmap\nmap.exe'))
    # Perform a more aggressive scan with OS detection and version detection
    nm.scan(ip, arguments='-sS -sV -O -Pn --script=default,vuln')
    return nm[ip]

if __name__ == "__main__":
    # Example usage
    target_ip = "192.168.124." + input("Enter the last octet of the IP to scan (e.g., 10): ")
    scan_result = deep_nmap_scan(target_ip)
    print(scan_result)