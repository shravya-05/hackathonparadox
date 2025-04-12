
from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import time
import joblib
import numpy as np
import pandas as pd
from threading import Thread, Event

# Configuration
TIME_WINDOW = 10          # Analysis window in seconds
THRESHOLD_PPS = 1000      # Packets/sec threshold
THRESHOLD_SYN = 500       # SYN packets/sec threshold
MODEL_PATH = "dos_model.pkl"
SCALER_PATH = "scaler.pkl"
INTERFACE = "en0"         # Use 'en0' for macOS Wi-Fi, 'en1' for Ethernet

# Features (MUST match training data)
features = [
    'total_packets', 
    'tcp_packets', 
    'udp_packets', 
    'icmp_packets',
    'syn_packets', 
    'unique_ips', 
    'avg_packet_len', 
    'ports_scanned'
]

# Global variables
packet_buffer = []
stop_sniffing = Event()

# Load model and scaler
try:
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
except FileNotFoundError:
    print(f"Error: Model files ({MODEL_PATH}, {SCALER_PATH}) not found!")
    print("Train the model first with train2.py")
    exit(1)

def extract_features(packets):
    """Extract features matching training data"""
    window_stats = defaultdict(int)
    src_ips = set()
    dst_ports = set()
    total_len = 0
    
    for pkt in packets:
        if IP in pkt:
            # Basic stats
            window_stats['total_packets'] += 1
            total_len += len(pkt)
            src_ips.add(pkt[IP].src)
            
            # Protocol-specific
            if TCP in pkt:
                window_stats['tcp_packets'] += 1
                if pkt[TCP].flags & 0x02:  # SYN flag check
                    window_stats['syn_packets'] += 1
                dst_ports.add(pkt[TCP].dport)
            elif UDP in pkt:
                window_stats['udp_packets'] += 1
                dst_ports.add(pkt[UDP].dport)
            elif ICMP in pkt:
                window_stats['icmp_packets'] += 1
    
    # Derived features
    window_stats['unique_ips'] = len(src_ips)
    window_stats['avg_packet_len'] = total_len / window_stats['total_packets'] if window_stats['total_packets'] else 0
    window_stats['ports_scanned'] = len(dst_ports)
    
    return [window_stats[f] for f in features]

def analyze_traffic():
    """Analyze traffic in time windows"""
    while not stop_sniffing.is_set():
        time.sleep(TIME_WINDOW)
        
        if packet_buffer:
            # Process current batch
            current_batch = packet_buffer.copy()
            packet_buffer.clear()
            
            # Extract features
            try:
                feature_vector = extract_features(current_batch)
                X = pd.DataFrame([feature_vector], columns=features)
                X_scaled = scaler.transform(X)
                
                # Model prediction
                pred = model.predict(X_scaled)
                anomaly_score = model.decision_function(X_scaled)[0]
                
                # Threshold checks
                pps = X['total_packets'].values[0] / TIME_WINDOW
                syn_pps = X['syn_packets'].values[0] / TIME_WINDOW
                
                if pred[0] == -1 or pps > THRESHOLD_PPS or syn_pps > THRESHOLD_SYN:
                    print(f"\n🚨 DOS ALERT! [Score: {anomaly_score:.2f}]")
                    print(f"📦 Packets/s: {pps:.1f} | 🔒 SYN/s: {syn_pps:.1f}")
                    print("📊 Traffic Summary:")
                    print(X.to_string(index=False, float_format="%.2f"))
                    print("-" * 50)
                    
            except Exception as e:
                print(f"Error analyzing batch: {str(e)}")

def packet_handler(packet):
    """Capture packets and store in buffer"""
    packet_buffer.append(packet)

def start_detection():
    """Start detection system"""
    print(f"🛡️ Starting DoS detection on {INTERFACE}...")
    print(f"⏱ Time window: {TIME_WINDOW}s | 📈 PPS threshold: {THRESHOLD_PPS}")
    print("Press Ctrl+C to stop monitoring\n")
    
    # Start analysis thread
    analyzer = Thread(target=analyze_traffic)
    analyzer.start()
    
    # Start sniffing
    try:
        sniff(prn=packet_handler, store=0, iface=INTERFACE)
    except KeyboardInterrupt:
        print("\n🛑 Stopping capture...")
    finally:
        stop_sniffing.set()
        analyzer.join()

if __name__ == "__main__":
    start_detection()