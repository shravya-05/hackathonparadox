import streamlit as st
import time
from datetime import datetime

st.set_page_config(page_title="Live DoS Detection", layout="wide", page_icon="🛡️")
st.title("🛡️ Network Threat Monitoring Dashboard")

LOG_FILE = "dos_output.log"

# Custom CSS
st.markdown("""
<style>
    .alert-box {
        padding: 1.2rem;
        border-radius: 0.75rem;
        margin: 1rem 0;
        box-shadow: 0 4px 10px rgba(0,0,0,0.1);
        font-family: 'Segoe UI', sans-serif;
    }
    .critical-alert {
        background-color: #ffdde0;
        border-left: 6px solid #d32f2f;
        color: #b71c1c;
    }
    .warning-alert {
        background-color: #fff4cc;
        border-left: 6px solid #ffa000;
        color: #795548;
    }
    .normal-traffic {
        background-color: #e3fce9;
        border-left: 6px solid #43a047;
        color: #2e7d32;
    }
    .log-timestamp {
        color: #555;
        font-size: 0.85rem;
        margin-bottom: 0.3rem;
        font-style: italic;
    }
    h4 {
        margin: 0.5rem 0 1rem 0;
        font-size: 1.2rem;
    }
    summary {
        font-weight: bold;
        margin-top: 0.5rem;
        cursor: pointer;
    }
    pre {
        background-color: #f5f5f5;
        padding: 0.75rem;
        border-radius: 0.5rem;
        font-size: 0.9rem;
        overflow-x: auto;
    }
</style>
""", unsafe_allow_html=True)

def safe_parse(value, type_func, default):
    """Safe value parsing with fallback"""
    try:
        return type_func(value)
    except (ValueError, TypeError):
        return default

def parse_log_entry(line):
    """Robust log parser with validation"""
    try:
        line = line.strip()
        if not line or line.startswith("timestamp|type|key=value"):
            return None
            
        parts = line.split("|")
        if len(parts) < 3:
            return None

        timestamp = parts[0]
        entry_type = parts[1]
        data = {}
        
        for item in parts[2:]:
            if "=" in item:
                key, val = item.split("=", 1)
                data[key] = val

        if entry_type == "ALERT":
            return {
                "type": "alert",
                "timestamp": timestamp,
                "score": safe_parse(data.get("score", 0), float, 0),
                "packets": safe_parse(data.get("packets", 0), float, 0),
                "syns": safe_parse(data.get("syns", 0), float, 0),
                "total": safe_parse(data.get("total", 0), int, 0),
                "ips": safe_parse(data.get("ips", 0), int, 0),
                "size": safe_parse(data.get("size", 0), float, 0)
            }
        elif entry_type == "ERROR":
            return {
                "type": "error",
                "timestamp": timestamp,
                "message": data.get("message", "Unknown error")
            }
        return None
    except Exception as e:
        st.error(f"Failed to parse log entry: {str(e)}")
        return None

def display_alert(alert):
    """Safe alert display with validation"""
    try:
        alert_class = "critical-alert" if alert.get('score', 0) > 0.7 else "warning-alert"
        st.markdown(f"""
        <div class="alert-box {alert_class}">
            <div class="log-timestamp">{alert.get('timestamp', '')}</div>
            <h4 styles="backgroundcolr=blue">🚨 Potential DoS Attack Detected</h4>
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem;">
                <div>
                    <div>Threat Score</div>
                    <h3 style="color: #d32f2f;">{alert.get('score', 0):.2f}</h3>
                </div>
                <div>
                    <div>Packets/s</div>
                    <h3>{alert.get('packets', 0):.1f}</h3>
                </div>
                <div>
                    <div>SYN/s</div>
                    <h3>{alert.get('syns', 0):.1f}</h3>
                </div>
            </div>
            <details>
                <summary>Technical Details</summary>
                <pre>Total Packets: {alert.get('total', 0)}\nUnique IPs: {alert.get('ips', 0)}\nAvg Size: {alert.get('size', 0):.1f} bytes</pre>
            </details>
        </div>
        """, unsafe_allow_html=True)
    except Exception as e:
        st.error(f"Display error: {str(e)}")

def main():
    """Main app with error containment"""
    st.sidebar.header("Configuration")
    refresh_rate = st.sidebar.slider("Update Frequency (seconds)", 1, 10, 2)
    max_alerts = st.sidebar.number_input("Max Alerts Displayed", 5, 50, 15)
    
    placeholder = st.empty()
    last_valid_log = None
    
    while True:
        try:
            with open(LOG_FILE, "r") as f:
                lines = f.readlines()[1:]  # Skip header
                logs = lines[-max_alerts:]
                
            with placeholder.container():
                st.subheader("Real-time Network Status")
                cols = st.columns(3)
                with cols[0]:
                    st.metric("Active Monitoring", "Enabled", "DoS Protection")
              
                with cols[2]:
                    st.metric("Detection Model", "Isolation Forest", "v1.0.2")
                
                st.subheader("Security Events Timeline")
                
                valid_entries = 0
                for line in reversed(logs):
                    entry = parse_log_entry(line)
                    if entry:
                        valid_entries += 1
                        if entry['type'] == 'alert':
                            display_alert(entry)
                        elif entry['type'] == 'error':
                            st.error(f"{entry['timestamp']} - {entry.get('message', 'Unknown error')}")
                        last_valid_log = time.time()
                    elif valid_entries == 0 and (time.time() - (last_valid_log or 0)) > 10:
                        st.markdown(f"""
                        <div class="alert-box normal-traffic">
                            <div class="log-timestamp">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
                            ✅ Normal network activity detected
                        </div>
                        """, unsafe_allow_html=True)
                
        except FileNotFoundError:
            st.warning("📡 Waiting for detection system to start...")
        except Exception as e:
            st.error(f"🚨 Critical interface error: {str(e)}")
        
        time.sleep(refresh_rate)

if __name__ == "__main__":
    main()