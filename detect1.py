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
    """Write structured alert data with validation"""
    try:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = (
            f"{timestamp}|ALERT|"
            f"score={alert_data.get('score', 0):.2f}|"
            f"packets={alert_data.get('packets_sec', 0):.1f}|"
            f"syns={alert_data.get('syn_sec', 0):.1f}|"
            f"total={alert_data.get('total_packets', 0)}|"
            f"ips={alert_data.get('unique_ips', 0)}|"
            f"size={alert_data.get('avg_pkt_size', 0):.1f}"
        )
        with open(LOG_FILE, "a") as f:
            f.write(log_entry + "\n")
    except Exception as e:
        print(f"Logging error: {str(e)}")

def log_error(error):
    """Write structured error data with validation"""
    try:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a") as f:
            f.write(f"{timestamp}|ERROR|message={str(error)[:200]}\n")
    except Exception as e:
        print(f"Error logging failed: {str(e)}")

try:
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
except FileNotFoundError as e:
    log_error(f"Model files missing: {str(e)}")
    exit(1)

def extract_features(packets):
    """Extract features with validation"""
    window_stats = defaultdict(int)
    src_ips = set()
    dst_ports = set()
    total_len = 0
    
    try:
        for pkt in packets:
            if IP in pkt:
                window_stats['total_packets'] += 1
                total_len += len(pkt)
                src_ips.add(pkt[IP].src)
                
                if TCP in pkt:
                    window_stats['tcp_packets'] += 1
                    if pkt[TCP].flags & 0x02:
                        window_stats['syn_packets'] += 1
                    dst_ports.add(pkt[TCP].dport)
                elif UDP in pkt:
                    window_stats['udp_packets'] += 1
                    dst_ports.add(pkt[UDP].dport)
                elif ICMP in pkt:
                    window_stats['icmp_packets'] += 1

        window_stats['unique_ips'] = len(src_ips)
        window_stats['avg_packet_len'] = total_len / window_stats['total_packets'] if window_stats['total_packets'] else 0
        window_stats['ports_scanned'] = len(dst_ports)
        
        return [window_stats.get(f, 0) for f in features]
    except Exception as e:
        log_error(f"Feature extraction failed: {str(e)}")
        return [0] * len(features)

def analyze_traffic():
    """Analysis with error containment"""
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
                        'score': max(min(anomaly_score, 1), -1),
                        'packets_sec': pps,
                        'syn_sec': syn_pps,
                        'total_packets': X['total_packets'].values[0],
                        'unique_ips': X['unique_ips'].values[0],
                        'avg_pkt_size': X['avg_packet_len'].values[0]
                    }
                    log_alert(alert_data)
                    
            except Exception as e:
                log_error(f"Analysis failed: {str(e)}")

def packet_handler(packet):
    """Packet capture with validation"""
    try:
        if IP in packet:
            packet_buffer.append(packet)
    except Exception as e:
        log_error(f"Packet handling error: {str(e)}")

def start_detection():
    """Main detection loop"""
    print(f"🛡️ Starting DoS detection on {INTERFACE}...")
    print(f"⏱ Time window: {TIME_WINDOW}s | 📈 PPS threshold: {THRESHOLD_PPS}")
    print("Press Ctrl+C to stop monitoring\n")
    
    analyzer = Thread(target=analyze_traffic)
    analyzer.start()
    
    try:
        sniff(prn=packet_handler, store=0, iface=INTERFACE)
    except KeyboardInterrupt:
        print("\n🛑 Stopping capture...")
    except Exception as e:
        log_error(f"Sniffing failed: {str(e)}")
    finally:
        stop_sniffing.set()
        analyzer.join()
        print("✅ Detection system shutdown complete")

if __name__ == "__main__":
    # Initialize log file with header
    with open(LOG_FILE, "w") as f:
        f.write("timestamp|type|key=value...\n")
    
    try:
        start_detection()
    except Exception as e:
        log_error(f"Fatal error: {str(e)}")
        print(f"⛔ Critical error: {str(e)}")