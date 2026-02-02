import streamlit as st
import pandas as pd
import joblib
import time
import os
import subprocess
import signal
import socket

# --- KONFIGURASI SISTEM ---
CONN_LOG = "conn.log"
SSL_LOG = "ssl.log"
NETWORK_INTERFACE = "en0" # Ganti ke 'eth0' jika di Linux (cek via 'ifconfig' atau 'ip a')
# NETWORK_INTERFACE = "lo0" # untuk pengecekan ip local

st.set_page_config(page_title="Live AI-IDS Smart Monitor", layout="wide")

# --- INITIALIZE SESSION STATE ---
if 'zeek_process' not in st.session_state:
    st.session_state.zeek_process = None
if 'listening' not in st.session_state:
    st.session_state.listening = False
if 'ssl_cache' not in st.session_state:
    st.session_state.ssl_cache = {} 
if 'history' not in st.session_state:
    st.session_state.history = pd.DataFrame(columns=['Time', 'Src_IP', 'Dest_IP', 'Service', 'SSL', 'Label', 'Confidence'])

st.title("🛡️ Live AI-IDS: Smart Monitoring")
st.write("Sistem Standby: Menunggu trafik dari DNS target untuk dianalisis oleh AI.")

# --- SIDEBAR: KONTROL ---
st.sidebar.header("📂 1. Load Brain AI")
uploaded_model = st.sidebar.file_uploader("Upload rf_model.pkl", type=["pkl"])
uploaded_encoder = st.sidebar.file_uploader("Upload encoders.pkl", type=["pkl"])

st.sidebar.divider()
st.sidebar.header("📡 2. Kontrol Jaringan")
target_dns = st.sidebar.text_input("🎯 DNS/Host Filter", placeholder="contoh: account.accurate.id")

# Tombol Start
if st.sidebar.button("🚀 Start Listening", disabled=st.session_state.listening):
    if uploaded_model and uploaded_encoder:
        # Hapus log lama agar data fresh
        for f in [CONN_LOG, SSL_LOG]:
            if os.path.exists(f): 
                try: os.remove(f)
                except: pass
            
        try:
            # Perintah dasar Zeek
            cmd = ["zeek", "-i", NETWORK_INTERFACE, "local"]
            
            if target_dns:
                # Bersihkan input DNS
                clean_dns = target_dns.replace("https://", "").replace("http://", "").split('/')[0]
                try:
                    # Ambil semua IP terkait (IPv4 & IPv6) agar filter tidak 'miss'
                    addr_info = socket.getaddrinfo(clean_dns, None)
                    ips = list(set([info[4][0] for info in addr_info]))
                    
                    # Bangun filter BPF: "host IP1 or host IP2"
                    filter_str = " or ".join([f"host {ip}" for ip in ips])
                    cmd.append(filter_str)
                    st.sidebar.success(f"Standby memantau {len(ips)} IP untuk {clean_dns}")
                except Exception as dns_err:
                    st.sidebar.warning(f"⚠️ DNS gagal di-resolve. Memantau seluruh trafik.")

            # Jalankan Zeek
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Beri jeda 3 detik untuk inisialisasi kernel pcap
            time.sleep(3)
            
            # Cek apakah Zeek 'mati' karena filter ditolak (fatal error: can't find host)
            if process.poll() is not None:
                err_msg = process.stderr.read()
                if "can't find host" in err_msg or "Permission denied" in err_msg:
                    st.error(f"❌ Zeek menolak filter: {err_msg}")
                    st.info("Beralih ke mode 'Listen All' (Tanpa Filter) agar sistem tetap aktif...")
                    process = subprocess.Popen(["zeek", "-i", NETWORK_INTERFACE, "local"])
                else:
                    st.error(f"Error fatal Zeek: {err_msg}")
                    st.stop()

            st.session_state.zeek_process = process
            st.session_state.listening = True
            st.rerun()
            
        except Exception as e:
            st.error(f"Gagal sistem: {e}")
    else:
        st.warning("⚠️ Upload Model & Encoder dulu!")

# Tombol Stop
if st.sidebar.button("🛑 Stop Listening", disabled=not st.session_state.listening):
    if st.session_state.zeek_process:
        os.kill(st.session_state.zeek_process.pid, signal.SIGTERM)
        st.session_state.zeek_process = None
        st.session_state.listening = False
        st.rerun()

# --- BAGIAN DASHBOARD MONITORING ---
if st.session_state.listening:
    st.write(f"🟢 **STATUS: LISTENING** pada `{NETWORK_INTERFACE}`" + (f" (Filter: `{target_dns}`)" if target_dns else ""))
    
    # Cek apakah file sudah tercipta
    if not os.path.exists(CONN_LOG):
        st.info("⌛ **Standby Mode**: Menunggu paket data pertama masuk. Silakan buka website target di browser.")
        time.sleep(3)
        st.rerun()
    else:
        # Load AI
        model = joblib.load(uploaded_model)
        encoders = joblib.load(uploaded_encoder)
        
        # Buka log dengan penanganan aman
        f_conn = open(CONN_LOG, "r")
        f_conn.seek(0, os.SEEK_END)
        
        f_ssl = None
        # ssl.log baru akan muncul jika ada trafik HTTPS
        if os.path.exists(SSL_LOG):
            f_ssl = open(SSL_LOG, "r")
            f_ssl.seek(0, os.SEEK_END)

        placeholder_table = st.empty()

        while st.session_state.listening:
            # 1. Pantau SSL.log (Jika sudah ada)
            if f_ssl:
                line_ssl = f_ssl.readline()
                if line_ssl and not line_ssl.startswith("#"):
                    p_s = line_ssl.strip().split('\t')
                    if len(p_s) > 10: st.session_state.ssl_cache[p_s[1]] = p_s[10]
            else:
                # Cek berkala apakah ssl.log sudah lahir
                if os.path.exists(SSL_LOG):
                    f_ssl = open(SSL_LOG, "r")
                    f_ssl.seek(0, os.SEEK_END)

            # 2. Pantau Conn.log
            line_conn = f_conn.readline()
            if not line_conn:
                time.sleep(0.1)
                continue

            if not line_conn.startswith("#"):
                p = line_conn.strip().split('\t')
                if len(p) < 12: continue
                
                uid = p[1]
                ssl_stat = st.session_state.ssl_cache.get(uid, 'F')

                # Fitur untuk AI
                input_data = {
                    'duration': float(p[8]) if p[8] != '-' else 0,
                    'orig_bytes': int(p[9]) if p[9] != '-' else 0,
                    'resp_bytes': int(p[10]) if p[10] != '-' else 0,
                    'orig_pkts': int(p[16]) if p[16] != '-' else 0,
                    'resp_pkts': int(p[18]) if p[18] != '-' else 0,
                    'proto': p[6], 'service': p[7] if p[7] != '-' else 'none', 'conn_state': p[11]
                }

                # Prediksi AI
                df_in = pd.DataFrame([input_data])
                for col in ['proto', 'service', 'conn_state']:
                    le = encoders[col]
                    val = str(df_in[col][0])
                    df_in[col] = le.transform([val])[0] if val in le.classes_ else -1

                try:
                    pred = model.predict(df_in)[0]
                    conf = model.predict_proba(df_in).max()
                except:
                    pred, conf = "Error", 0.0

                # Update Tabel UI
                new_row = {
                    'Time': time.strftime("%H:%M:%S"),
                    'Src_IP': p[2], 'Dest_IP': p[4], 'Service': p[7],
                    'SSL': "OK" if ssl_stat == 'T' else "FAIL",
                    'Label': pred, 'Confidence': f"{conf:.2%}"
                }
                
                # Tambahkan baris baru ke history dan RESET INDEX
                st.session_state.history = pd.concat(
                    [pd.DataFrame([new_row]), st.session_state.history], 
                    ignore_index=True
                ).head(100)
                
                with placeholder_table:
                    # Tampilkan dengan highlight merah untuk label serangan
                    st.dataframe(
                        st.session_state.history.style.apply(
                            lambda x: ['background-color: #ffcccc' if x.Label != 'Normal' else '' for _ in x], 
                            axis=1
                        ), 
                        width="stretch"
                    )
else:
    st.info("💡 **Mode Idle**: Silakan upload model dan klik 'Start Listening'.")