import scapy
from scapy.all import send, IP, TCP, UDP, ICMP  # Added missing protocol classes
import random
import time

target_ip = "172.20.10.10"
iface = "lo0"

def port_scan_simulation(target, ports=range(20, 100)):
    print("[*] Starting port scan simulation...")
    for port in ports:
        pkt = IP(dst=target)/TCP(dport=port, flags="S")  # SYN packet
        send(pkt, iface=iface, verbose=0)  # Added interface specification
        time.sleep(0.05)

def ping_flood_simulation(target, count=500000):
    print("[*] Starting ICMP (ping) flood simulation...")
    for _ in range(count):
        pkt = IP(dst=target)/ICMP()
        send(pkt, iface=iface, verbose=0)
        

def udp_flood_simulation(target, count=100):
    print("[*] Starting UDP flood simulation...")
    for _ in range(count):
        port = random.randint(1024, 65535)
        payload = bytes(random.getrandbits(8) for _ in range(32))
        pkt = IP(dst=target)/UDP(dport=port)/payload
        send(pkt, iface=iface, verbose=0)
        time.sleep(0.01)

# Run simulations
port_scan_simulation(target_ip)
ping_flood_simulation(target_ip)
udp_flood_simulation(target_ip)

print("Simulated traffic completed")