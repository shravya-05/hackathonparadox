from scapy.all import sniff, IP
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP, ICMP

import pandas as pd
import time

packet_list = []

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        proto_name = ''
        if TCP in packet:
            proto_name = 'TCP'
        elif UDP in packet:
            proto_name = 'UDP'
        elif ICMP in packet:
            proto_name = 'ICMP'
        else:
            proto_name = str(ip_layer.proto)

        packet_info = {
            'src': ip_layer.src,
            'dst': ip_layer.dst,
            'proto': proto_name,
            'len': len(packet),
            'time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        }

        packet_list.append(packet_info)
        print(packet_info)

print("Capturing packets for 30 seconds...")
sniff(prn=process_packet, timeout=30, store=0)

# Save to CSV
df = pd.DataFrame(packet_list)
df.to_csv("captured_traffic.csv", index=False)
print("Saved to captured_traffic.csv")
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Use only numerical features
X = df[['len']].copy()
X['proto_num'] = df['proto'].map({'TCP': 1, 'UDP': 2, 'ICMP': 3}).fillna(0)

# Normalize
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Train model
model = IsolationForest(contamination=0.05, random_state=42)
df['anomaly'] = model.fit_predict(X_scaled)

# Show anomalies
anomalies = df[df['anomaly'] == -1]
print(f"Anomalies detected: {len(anomalies)}")
print(anomalies.head())
