import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

# Load previous traffic data (or use captured_traffic.csv)
df = pd.read_csv("captured_traffic.csv")

# Convert protocol to numeric values
df['proto_num'] = df['proto'].map({'TCP': 1, 'UDP': 2, 'ICMP': 3}).fillna(0)

X = df[['len', 'proto_num']]
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

model = IsolationForest(contamination=0.01, random_state=42)
model.fit(X_scaled)

# Save model and scaler
joblib.dump(model, "isoforest_model.pkl")
joblib.dump(scaler, "scaler.pkl")

print("Model and scaler saved!")
