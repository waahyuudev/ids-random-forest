import streamlit as st
import socket
import ssl
import threading
import time

st.set_page_config(page_title="Red Team: Attack Simulator", page_icon="🔥", layout="wide")

# --- UI Header ---
st.title("🔥 Red Team Attack Simulator")
st.write("Gunakan alat ini untuk menguji sensitivitas model **Random Forest** pada IDS Anda.")

# --- Sidebar Configuration ---
st.sidebar.header("🎯 Target Configuration")
# Perbaikan: Menambahkan help untuk edukasi input yang benar
target_input = st.sidebar.text_input("Target DNS/IP", value="127.0.0.1", help="Jangan gunakan http:// atau akhiran /")
intensity = st.sidebar.slider("Attack Intensity (Requests)", 5, 100, 20)
delay = st.sidebar.slider("Delay between packets (sec)", 0.0, 1.0, 0.1)

# --- Session State Management ---
if 'attack_logs' not in st.session_state:
    st.session_state.attack_logs = []
if 'is_attacking' not in st.session_state:
    st.session_state.is_attacking = False

def log_event(msg):
    st.session_state.attack_logs.insert(0, f"[{time.strftime('%H:%M:%S')}] {msg}")

# --- Utility: Sanitize Input ---
def get_clean_host(target):
    # Menghapus protokol dan path agar tidak error 'nodename not known'
    return target.replace("https://", "").replace("http://", "").split('/')[0].strip()

# --- Attack Functions ---
def run_port_scan(target, count, sleep_time):
    st.session_state.is_attacking = True
    host = get_clean_host(target)
    log_event(f"🚀 Starting Port Scan on {host}...")
    
    try:
        ip = socket.gethostbyname(host)
        ports = [80, 443, 8080, 21, 22, 23, 25, 53, 3306, 5432, 1337, 31337]
        for i in range(min(count, len(ports))):
            port = ports[i]
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            # connect_ex mengembalikan 0 jika sukses, selain itu gagal (REJ)
            result = s.connect_ex((ip, port))
            status = "SUCCESS" if result == 0 else "REJECTED"
            log_event(f"Probing Port {port}... {status}")
            s.close()
            time.sleep(sleep_time)
        log_event("✅ Port Scan simulation finished.")
    except Exception as e:
        log_event(f"❌ DNS Error: {e}")
    finally:
        st.session_state.is_attacking = False

def run_tls_ddos(target, count, sleep_time):
    st.session_state.is_attacking = True
    host = get_clean_host(target)
    log_event(f"🔥 Starting TLS DDoS on {host}...")
    
    for i in range(count):
        try:
            # Simulasi Handshake yang digantung/diputus (Abnormal)
            sock = socket.create_connection((host, 443), timeout=1)
            # Sengaja tidak memanggil context.wrap_socket() agar Zeek mencatat 'Established = F'
            log_event(f"Burst {i+1}: TCP SYN sent to 443, dropping before SSL completion.")
            sock.close()
        except Exception as e:
            log_event(f"⚠️ Connection failed: {e}")
        time.sleep(sleep_time)
    
    log_event("✅ TLS DDoS simulation finished.")
    st.session_state.is_attacking = False

# --- UI Layout ---
col1, col2 = st.columns(2)

with col1:
    st.subheader("1. Port Scanning")
    st.info("Mensimulasikan pencarian port (memicu status REJ di Zeek).")
    if st.button("Launch Scan", type="primary", use_container_width=True, disabled=st.session_state.is_attacking):
        run_port_scan(target_input, intensity, delay)

with col2:
    st.subheader("2. TLS DDoS")
    st.info("Mensimulasikan kegagalan SSL Handshake (memicu ssl.log fail).")
    if st.button("Launch DDoS", type="primary", use_container_width=True, disabled=st.session_state.is_attacking):
        run_tls_ddos(target_input, intensity, delay)

st.divider()

# --- Attack Console ---
st.subheader("📟 Attack Console Output")
c1, c2 = st.columns([1, 5])
with c1:
    if st.button("Clear Console", use_container_width=True):
        st.session_state.attack_logs = []
        st.rerun()

if st.session_state.attack_logs:
    st.code("\n".join(st.session_state.attack_logs), language="bash")
else:
    st.caption("No attacks launched yet. Ready for simulation.")