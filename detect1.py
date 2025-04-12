from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import time
import joblib
import pandas as pd
from threading import Thread, Event

# Configuration
TIME_WINDOW = 10          # Analysis window in seconds
THRESHOLD_PPS = 1000      # Packets/sec threshold
THRESHOLD_SYN = 500       # SYN packets/sec threshold
MODEL_PATH = "dos_model.pkl"
SCALER_PATH = "scaler.pkl"
INTERFACE = "en0"         # macOS Wi-Fi interface
LOG_FILE = "dos_output.log"

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

def log_alert(alert_data):
    """Write structured alert data"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    log_entry = (
        f"{timestamp}|ALERT|"
        f"score={alert_data['score']:.2f}|"
        f"packets={alert_data['packets_sec']:.1f}|"
        f"syns={alert_data['syn_sec']:.1f}|"
        f"total={alert_data['total_packets']}|"
        f"ips={alert_data['unique_ips']}|"
        f"size={alert_data['avg_pkt_size']:.1f}"
    )
    with open(LOG_FILE, "a") as f:
        f.write(log_entry + "\n")

def log_error(error):
    """Write structured error data"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp}|ERROR|message={error}\n")

try:
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
except FileNotFoundError as e:
    log_error(f"Model files missing: {str(e)}")
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
                if pkt[TCP].flags & 0x02:  # SYN flag
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
            try:
                current_batch = packet_buffer.copy()
                packet_buffer.clear()
                
                feature_vector = extract_features(current_batch)
                X = pd.DataFrame([feature_vector], columns=features)
                X_scaled = scaler.transform(X)
                
                pred = model.predict(X_scaled)
                anomaly_score = model.decision_function(X_scaled)[0]
                pps = X['total_packets'].values[0] / TIME_WINDOW
                syn_pps = X['syn_packets'].values[0] / TIME_WINDOW
                
                if pred[0] == -1 or pps > THRESHOLD_PPS or syn_pps > THRESHOLD_SYN:
                    alert_data = {
                        'score': round(anomaly_score, 2),
                        'packets_sec': round(pps, 1),
                        'syn_sec': round(syn_pps, 1),
                        'total_packets': X['total_packets'].values[0],
                        'unique_ips': X['unique_ips'].values[0],
                        'avg_pkt_size': round(X['avg_packet_len'].values[0], 1)
                    }
                    log_alert(alert_data)
                    
            except Exception as e:
                log_error(f"Analysis error: {str(e)}")

def packet_handler(packet):
    """Capture packets and store in buffer"""
    packet_buffer.append(packet)

def start_detection():
    """Start detection system"""
    print(f"🛡️ Starting DoS detection on {INTERFACE}...")
    print(f"⏱ Time window: {TIME_WINDOW}s | 📈 PPS threshold: {THRESHOLD_PPS}")
    print("Press Ctrl+C to stop monitoring\n")
    
    analyzer = Thread(target=analyze_traffic)
    analyzer.start()
    
    try:
        sniff(prn=packet_handler, store=0, iface=INTERFACE)
    except KeyboardInterrupt:
        print("\n🛑 Stopping capture...")
    finally:
        stop_sniffing.set()
        analyzer.join()
        print("✅ Detection system shutdown complete")

if __name__ == "__main__":
    # Initialize log file
    with open(LOG_FILE, "w") as f:
        f.write("DOS Detection System Log\n")
        f.write("="*40 + "\n")
    
    try:
        start_detection()
    except Exception as e:
        log_error(f"Fatal error: {str(e)}")
        print(f"⛔ Critical error: {str(e)}")