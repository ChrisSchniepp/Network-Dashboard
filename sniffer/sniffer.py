from scapy.all import ARP, Ether, srp, srp1, IP, UDP, DNS, DNSQR
import socket
import os
import time
from mac_vendor_lookup import MacLookup
#import deep_scan
from . import deep_scan

def check_and_update_mac_vendors():
    """Checks if the MAC vendor database needs updating (older than 30 days or missing)."""
    # Make path relative to this script file, not the execution directory
    script_dir = os.path.dirname(__file__)
    timestamp_file = os.path.join(script_dir, "mac_vendors_update.txt")
    update_interval = 30 * 24 * 60 * 60  # 30 days in seconds
    
    needs_update = False
    if not os.path.exists(timestamp_file):
        needs_update = True
    else:
        try:
            with open(timestamp_file, "r") as f:
                last_update = float(f.read().strip())
                if time.time() - last_update > update_interval:
                    needs_update = True
        except (ValueError, OSError):
            needs_update = True
            
    if needs_update:
        print("Updating MAC vendor database (runs once every 30 days)...")
        MacLookup().update_vendors()
        try:
            with open(timestamp_file, "w") as f:
                f.write(str(time.time()))
        except OSError:
            pass

def get_hostname(ip):
    try:
        #print(socket.gethostbyaddr(ip))
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        #print(f"Could not resolve hostname for {ip}")
        return "Unknown"
    
def get_mdns_hostname(ip, timeout=1):
    """Attempts to get a hostname using mDNS (Bonjour/Avahi), common for TVs and Apple devices."""
    # Format the IP for a reverse PTR query
    reversed_ip = '.'.join(ip.split('.')[::-1]) + ".in-addr.arpa"
    
    # Build the mDNS query packet to the standard multicast address
    mdns_query = Ether(dst="01:00:5e:00:00:fb") / IP(dst="224.0.0.251") / UDP(sport=5353, dport=5353) / DNS(
        id=0,
        qr=0, # It's a query
        opcode=0,
        qd=DNSQR(qname=reversed_ip, qtype='PTR')
    )
    
    try:
        # Send the packet and wait for a single response
        ans = srp1(mdns_query, timeout=timeout, verbose=0, iface_hint=ip)
        
        # Check if we got a DNS answer
        if ans and ans.haslayer(DNS) and ans[DNS].an:
            # Iterate through DNS answers to find the PTR record
            for i in range(ans[DNS].ancount):
                answer = ans[DNS].an[i]
                if answer.type == 12: # 12 = PTR record type
                    hostname = answer.rdata.decode('utf-8').rstrip('.local.')
                    return hostname
    except Exception:
        pass # Ignore any scapy/socket errors
    return "Unknown"

def get_open_ports(ip):
    """Scans common ports to help identify the device."""
    open_ports = []
    # 22(SSH), 80(HTTP), 443(HTTPS), 445(SMB/Windows), 3389(RDP), 8080(Alt HTTP), 62078(Apple Sync)
    common_ports = [22, 80, 443, 445, 3389, 8080, 62078]
    for port in common_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)  # Fast timeout so the scan doesn't hang
        if s.connect_ex((ip, port)) == 0:
            open_ports.append(port)
        s.close()
    return open_ports

def categorize_device(vendor, hostname, open_ports):
    """Categorizes the device based on vendor, hostname, and open ports."""
    vendor_lower = vendor.lower()
    hostname_lower = hostname.lower()
    
    # 1. Networking Equipment
    if any(v in vendor_lower for v in ['netgear', 'cisco', 'ubiquiti', 'tp-link', 'asus', 'aruba']):
        return "Networking"
        
    # 2. IoT / Smart Home / Entertainment
    if any(v in vendor_lower for v in ['amazon', 'roku', 'sonos', 'philips', 'ring', 'nest', 'lg', 'vizio', 'tcl']):
        return "IoT / Smart TV"
    if any(k in hostname_lower for k in ['tv', 'chromecast', 'roku', 'sonos', 'hue']):
        return "IoT / Smart TV"
        
    # 3. Computers / Servers
    if 3389 in open_ports or 445 in open_ports:
        return "Computer (Windows)"
    if 22 in open_ports and "apple" not in vendor_lower:
        return "Computer / Server (Linux)"
    if any(v in vendor_lower for v in ['dell', 'hp', 'lenovo', 'micro-star', 'asustek']):
        return "Computer"
    if any(k in hostname_lower for k in ['macbook', 'imac', 'desktop', 'laptop', 'pc']):
        return "Computer"
        
    # 4. Mobile / Tablets
    if 'apple' in vendor_lower and not any(k in hostname_lower for k in ['macbook', 'imac']):
        return "Mobile / Tablet (Apple)"
    if any(v in vendor_lower for v in ['samsung', 'google', 'motorola', 'oneplus', 'huawei']):
        return "Mobile / Tablet"
        
    return "Unknown / Other"

def scan_and_organize(ip_range):
    check_and_update_mac_vendors()
    mac_lookup = MacLookup()
    
    # 1. ARP Scan
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    answered = srp(broadcast/arp_request, timeout=2, verbose=False)[0]
    
    results = []
    for _, received in answered:
        ip = received.psrc
        mac = received.hwsrc
        
        # 2. Enrich Data
        try:
            vendor = mac_lookup.lookup(mac)
        except Exception:
            # Check if MAC is locally administered (randomized) by checking the 2nd bit of the 1st octet
            #first_octet = int(mac.split(':')[0], 16)
            #if first_octet & 2:
            #    vendor = "Unknown (Randomized MAC)"
            #else:
            vendor = "Unknown"

        # First, try the more reliable mDNS for friendly names, then fall back to standard DNS
        hostname = get_mdns_hostname(ip)
        if hostname == "Unknown":
            hostname = get_hostname(ip)

        # Heuristic: If vendor is unknown but hostname suggests Apple, fix it.
        if vendor == "Unknown":
            deep_scan_result = deep_scan.deep_nmap_scan(ip)
            
            # Extract Main Vendor
            if deep_scan_result.get('vendor'):
                vendor_dict = deep_scan_result['vendor']
                if vendor_dict:
                    vendor = list(vendor_dict.values())[0] + " (nmap)"
            # Extract OS Class Vendor if main vendor is missing
            elif deep_scan_result.get('osmatch'):
                osmatch = deep_scan_result['osmatch']
                if osmatch and osmatch[0].get('osclass'):
                    os_vendor = osmatch[0]['osclass'][0].get('vendor')
                    if os_vendor:
                        vendor = os_vendor + " (nmap OS)"
                        
            # Extract Hostname
            if hostname == "Unknown" and deep_scan_result.get('hostnames'):
                hostnames = deep_scan_result['hostnames']
                if hostnames and hostnames[0].get('name'):
                    hostname = hostnames[0]['name'] + " (nmap)"

        open_ports = get_open_ports(ip)
            
        category = categorize_device(vendor, hostname, open_ports)
        
        results.append({
            'ip': ip,
            'mac': mac,
            'hostname': hostname,
            'vendor': vendor,
            'open_ports': str(open_ports) if open_ports else "None",
            'category': category
        })
        
    return results

if __name__ == "__main__":
    # Example display logic
    devices = scan_and_organize("192.168.124.0/24")
    # Sort by Hostname
    for dev in sorted(devices, key=lambda x: x['hostname']):
        print(f"[{dev['category']}] {dev['hostname']} ({dev['ip']}) - Vendor: {dev['vendor']} | Ports: {dev['open_ports']}")