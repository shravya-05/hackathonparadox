# frontend.py
import streamlit as st
import time
import os
from datetime import datetime

st.set_page_config(page_title="Live DoS Detection", layout="wide", page_icon="🛡️")
st.title("🛡️ Network Threat Monitoring Dashboard")

LOG_FILE = "dos_output.log"

# Custom CSS
st.markdown("""
<style>
    .alert-box {
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 1rem 0;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .critical-alert {
        background-color: #ffebee;
        border-left: 5px solid #ff5252;
    }
    .warning-alert {
        background-color: #fff3e0;
        border-left: 5px solid #ff9100;
    }
    .normal-traffic {
        background-color: #e8f5e9;
        border-left: 5px solid #4caf50;
    }
    .log-timestamp {
        color: #666;
        font-size: 0.8rem;
    }
</style>
""", unsafe_allow_html=True)

def parse_log_entry(line):
    """Convert log line to structured data"""
    if "ALERT" in line:
        return {
            "type": "alert",
            "timestamp": line.split(" | ")[0],
            "score": float(line.split("Score: ")[1].split(" |")[0]),
            "packets": float(line.split("Packets/s: ")[1].split(" |")[0]),
            "syns": float(line.split("SYN/s: ")[1].split("\n")[0]),
            "details": "\n".join(line.split("\n")[1:-1])
        }
    elif "ERROR" in line:
        return {
            "type": "error",
            "timestamp": line.split(" | ")[0],
            "message": line.split("ERROR | ")[1]
        }
    return None

def display_alert(alert):
    """Display formatted alert"""
    alert_class = "critical-alert" if alert['score'] > 0.7 else "warning-alert"
    st.markdown(f"""
    <div class="alert-box {alert_class}">
        <div class="log-timestamp">{alert['timestamp']}</div>
        <h4>🚨 Potential DoS Attack Detected</h4>
        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem;">
            <div>
                <div>Threat Score</div>
                <h3 style="color: #d32f2f;">{alert['score']:.2f}</h3>
            </div>
            <div>
                <div>Packets/s</div>
                <h3>{alert['packets']:.1f}</h3>
            </div>
            <div>
                <div>SYN/s</div>
                <h3>{alert['syns']:.1f}</h3>
            </div>
        </div>
        <details>
            <summary>Technical Details</summary>
            <pre>{alert['details']}</pre>
        </details>
    </div>
    """, unsafe_allow_html=True)

def display_metrics():
    """Display real-time metrics"""
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Current Threat Level", "HIGH", delta="+12%", delta_color="inverse")
    with col2:
        st.metric("Active Connections", "1,234", "-5% from normal")
    with col3:
        st.metric("Network Throughput", "2.4 Gbps", "+18%")

def main():
    """Main app function"""
    st.sidebar.header("Configuration")
    refresh_rate = st.sidebar.slider("Update Frequency (seconds)", 1, 10, 2)
    max_alerts = st.sidebar.number_input("Max Alerts Displayed", 5, 50, 15)
    
    placeholder = st.empty()
    
    while True:
        try:
            with open(LOG_FILE, "r") as f:
                logs = f.readlines()[-max_alerts:]
                
            with placeholder.container():
                display_metrics()
                st.subheader("Recent Security Events")
                
                for line in reversed(logs):
                    entry = parse_log_entry(line.strip())
                    if entry:
                        if entry['type'] == 'alert':
                            display_alert(entry)
                        elif entry['type'] == 'error':
                            st.error(f"{entry['timestamp']} - {entry['message']}")
                    else:
                        st.markdown(f"""
                        <div class="alert-box normal-traffic">
                            <div class="log-timestamp">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
                            ✅ Normal network activity detected
                        </div>
                        """, unsafe_allow_html=True)
                
        except FileNotFoundError:
            st.warning("Waiting for detection system to start...")
        except Exception as e:
            st.error(f"Error reading logs: {str(e)}")
        
        time.sleep(refresh_rate)

if __name__ == "__main__":
    main()