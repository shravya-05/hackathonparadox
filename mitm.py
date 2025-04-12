from scapy.all import sniff, ARP, DNS, DNSQR, DNSRR, IP
from collections import defaultdict
import netifaces
import time
import threading
import getmac

# Configuration
INTERFACE = "en0"              # Network interface (en0 for macOS)
CHECK_INTERVAL = 10            # Check for anomalies every 10 seconds
ARP_THRESHOLD = 5              # Max ARP packets/sec from single MAC
TRUSTED_DNS_SERVERS = ["8.8.8.8", "1.1.1.1"]  # Google/Cloudflare DNS

# Get gateway info for macOS
gateways = netifaces.gateways()
default_gateway_info = gateways['default'][netifaces.AF_INET]
default_gateway_ip, default_gateway_interface = default_gateway_info[0], default_gateway_info[1]

# Get gateway MAC using getmac
try:
    default_gateway_mac = getmac.get_mac_address(ip=default_gateway_ip)
except Exception as e:
    print(f"Error getting gateway MAC: {str(e)}")
    exit(1)

# State tracking
arp_table = {}
mac_arp_count = defaultdict(int)
dns_query_map = defaultdict(list)

def get_vendor(mac):
    """Get vendor from MAC (optional)"""
    # Implement OUI lookup here or use a library
    return "Unknown"

def detect_arp_spoof(pkt):
    if ARP in pkt and pkt[ARP].op == 2:  # ARP response
        src_ip = pkt[ARP].psrc
        src_mac = pkt[ARP].hwsrc
        
        # Check gateway MAC spoofing
        if src_ip == default_gateway_ip and src_mac != default_gateway_mac:
            print(f"🚨 ARP Spoof Alert! Fake gateway MAC: {src_mac} (Real: {default_gateway_mac})")
        
        # Check IP-MAC conflicts
        if src_ip in arp_table and arp_table[src_ip] != src_mac:
            old_mac = arp_table[src_ip]
            print(f"🚨 ARP Conflict: {src_ip} changed from {old_mac} to {src_mac}")
        
        arp_table[src_ip] = src_mac
        mac_arp_count[src_mac] += 1

def detect_dns_spoof(pkt):
    if DNS in pkt and pkt[DNS].qr == 1:  # DNS response
        for x in range(pkt[DNS].ancount):
            answer = pkt[DNS].an[x]
            if answer.type == 1:  # A record
                query = pkt[DNSQR].qname.decode()
                resp_ip = answer.rdata
                dns_server = pkt[IP].src
                
                if dns_server not in TRUSTED_DNS_SERVERS:
                    print(f"🚨 Suspicious DNS Response: {query} -> {resp_ip} from {dns_server}")

def monitor_arp_rates():
    """Check for ARP flooding"""
    while True:
        time.sleep(CHECK_INTERVAL)
        for mac, count in mac_arp_count.items():
            rate = count / CHECK_INTERVAL
            if rate > ARP_THRESHOLD:
                vendor = get_vendor(mac)
                print(f"⚠️ ARP Flood: {mac} ({vendor}) - {rate:.1f} pkts/sec")
        mac_arp_count.clear()

def start_mitm_detection():
    print(f"🛡️ Starting MITM detection on {INTERFACE}")
    print(f"Default Gateway: {default_gateway_ip} ({default_gateway_mac})")
    print("Monitoring for:")
    print("- ARP spoofing/conflicts")
    print("- DNS spoofing")
    print("- ARP flooding\n")
    
    # Start ARP rate monitor thread
    threading.Thread(target=monitor_arp_rates, daemon=True).start()
    
    # Start sniffing
    sniff(
        filter="arp or (udp port 53)", 
        prn=lambda pkt: (detect_arp_spoof(pkt), detect_dns_spoof(pkt)),
        iface=INTERFACE,
        store=0
    )

if __name__ == "__main__":
    try:
        start_mitm_detection()
    except KeyboardInterrupt:
        print("\n🛑 MITM detection stopped")