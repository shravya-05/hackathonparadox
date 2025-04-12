from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import numpy as np
import pandas as pd
import joblib

# Define features to match detection code
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

def generate_data(num_samples=10000):
    data = []
    # Normal traffic (50%)
    for _ in range(num_samples//2):
        data.append([
            np.random.randint(50, 500),   # total_packets
            np.random.randint(20, 300),   # tcp_packets
            np.random.randint(0, 100),    # udp_packets
            np.random.randint(0, 50),     # icmp_packets
            np.random.randint(0, 150),    # syn_packets
            np.random.randint(10, 200),   # unique_ips
            np.random.uniform(64, 1500),  # avg_packet_len
            np.random.randint(1, 50)     # ports_scanned
        ])
    
    # Attack traffic (50%)
    for _ in range(num_samples//2):
        data.append([
            np.random.randint(800, 5000), 
            np.random.randint(500, 4000),
            np.random.randint(0, 1000),
            np.random.randint(0, 100),
            np.random.randint(400, 3000),
            np.random.randint(1, 10),
            np.random.uniform(64, 1500),
            np.random.randint(50, 65535)
        ])
    
    return pd.DataFrame(data, columns=features)

# Train and save
df = generate_data()
X_train, X_test = train_test_split(df, test_size=0.2)
scaler = StandardScaler().fit(X_train)
model = IsolationForest(n_estimators=100, contamination=0.1).fit(scaler.transform(X_train))

joblib.dump(model, "dos_model.pkl")
joblib.dump(scaler, "scaler.pkl")