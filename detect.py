from scapy.all import sniff, IP, TCP, UDP, ICMP
import pandas as pd
import time
import joblib
from sklearn.preprocessing import StandardScaler

# Load trained model and scaler
model = joblib.load("isoforest_model.pkl")
scaler = joblib.load("scaler.pkl")

def detect_anomaly(packet):
    if IP in packet:
        ip_layer = packet[IP]
        proto = 0
        if TCP in packet:
            proto = 1
        elif UDP in packet:
            proto = 2
        elif ICMP in packet:
            proto = 3

        pkt_len = len(packet)
        df = pd.DataFrame([[pkt_len, proto]], columns=['len', 'proto_num'])
        X_scaled = scaler.transform(df)
        pred = model.predict(X_scaled)

        if pred[0] == -1:
            print("🚨 Anomaly Detected!")
            print(f"Source: {ip_layer.src}, Destination: {ip_layer.dst}, Proto: {proto}, Length: {pkt_len}")

def start_sniffing():
    print("🔍 Starting real-time anomaly detection...")
    sniff(prn=detect_anomaly, store=0)

if __name__ == "__main__":
    start_sniffing()