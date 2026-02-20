import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import time
import os
from preprocess_engineering import process_logs
from train import train_rf_model

# --- KONFIGURASI HALAMAN ---
st.set_page_config(page_title="AI IDS Pro Dashboard", layout="wide")
st.title("AI-Powered Intrusion Detection System")
st.write("Sistem Monitoring Terintegrasi: Upload -> Preprocess -> Train -> Visualize")

# --- SIDEBAR: UPLOAD DATA ---
st.sidebar.header("1. Upload Data Log")
conn_file = st.sidebar.file_uploader("Upload conn.log", type=["log", "txt"])
ssl_file = st.sidebar.file_uploader("Upload ssl.log", type=["log", "txt"])

if conn_file and ssl_file:
    # --- TAHAP 1: PREPROCESSING ---
    st.subheader("Data Processing & Engineering")
    with st.status("Mengolah log jaringan...", expanded=False) as status:
        st.write("Membaca file log...")
        time.sleep(0.5) 
        # Memanggil fungsi dari preprocess_engineering.py
        df = process_logs(conn_file, ssl_file)
        st.write("Melakukan merging data dan labeling...")
        time.sleep(0.5)
        status.update(label="Preprocessing Selesai!", state="complete")
    
    st.success(f"Dataset siap dengan {len(df)} baris data.")

    # --- TAHAP 2: TRAINING & EVALUASI ---
    st.divider()
    st.subheader("Model Training & Evaluation")
    
    # Session state agar data tidak hilang saat filter diubah
    if 'model_trained' not in st.session_state:
        st.session_state.model_trained = False

    if st.button("Mulai Latih Model AI"):
        with st.spinner("Melatih model Random Forest..."):
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            for i in range(1, 101, 25):
                status_text.text(f"Proses pelatihan: {i}%")
                progress_bar.progress(i)
                time.sleep(0.3)
                
            # Memanggil fungsi dari train.py
            model, features, importances, metrics = train_rf_model(df)
            
            # Simpan hasil ke session state
            st.session_state.model_trained = True
            st.session_state.features = features
            st.session_state.importances = importances
            st.session_state.metrics = metrics
            
            progress_bar.progress(100)
            status_text.text("Pelatihan Selesai! Model siap digunakan.")
        st.success("Model Berhasil Dilatih!")

    # --- TAHAP 3: VISUALISASI PERFORMA ---
    if st.session_state.model_trained:
        # Menampilkan Metrik Utama (Cards)
        m_col1, m_col2, m_col3, m_col4 = st.columns(4)
        m_col1.metric("Accuracy", f"{st.session_state.metrics['accuracy']:.2%}")
        m_col2.metric("Precision", f"{st.session_state.metrics['precision']:.2%}")
        m_col3.metric("Recall", f"{st.session_state.metrics['recall']:.2%}")
        m_col4.metric("F1-Score", f"{st.session_state.metrics['f1']:.2%}")

        col_vis1, col_vis2 = st.columns(2)
        
        with col_vis1:
            st.subheader("Komposisi Keamanan")
            fig1, ax1 = plt.subplots()
            df['label'].value_counts().plot(kind='pie', autopct='%1.1f%%', ax=ax1, 
                                            colors=['#2ecc71', '#e74c3c', '#f1c40f'])
            st.pyplot(fig1)

        with col_vis2:
            st.subheader("Indikator Serangan Terkuat")
            fig2, ax2 = plt.subplots()
            feat_imp = pd.Series(st.session_state.importances, index=st.session_state.features).sort_values()
            feat_imp.plot(kind='barh', ax=ax2, color='teal')
            st.pyplot(fig2)

        # Grafik Metrik Bar
        st.subheader("Grafik Performa Model")
        fig_met, ax_met = plt.subplots(figsize=(10, 4))
        m_names = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
        m_vals = [
            st.session_state.metrics['accuracy'], 
            st.session_state.metrics['precision'], 
            st.session_state.metrics['recall'], 
            st.session_state.metrics['f1']
        ]
        bars = ax_met.bar(m_names, m_vals, color=['#4CAF50', '#2196F3', '#FF9800', '#F44336'])
        ax_met.set_ylim(0, 1.1)
        for bar in bars:
            yval = bar.get_height()
            ax_met.text(bar.get_x() + bar.get_width()/2, yval + 0.02, f'{yval:.2%}', ha='center', va='bottom', fontweight='bold')
        st.pyplot(fig_met)

        # --- TAHAP 4: DOWNLOAD CENTER ---
        st.divider()
        st.subheader("Download Center")
        dl_col1, dl_col2, dl_col3 = st.columns(3)
        
        # Fitur yang ditampilkan di dashboard (Technical Header)
        export_features = ['uid', 'id.orig_h', 'id.resp_h', 'id.resp_p', 'service', 'conn_state', 'label']

        with dl_col1:
            # Download Dataset Teknis (Hanya kolom dashboard & mengikuti filter)
            current_choice = st.session_state.get('filter_choice', 'Semua')
            filtered_df = df if current_choice == "Semua" else df[df['label'] == current_choice]
            csv_data = filtered_df[export_features].to_csv(index=False).encode('utf-8')
            
            st.download_button(
                label="Download Dataset (Technical)", 
                data=csv_data, 
                file_name='ids_technical_export.csv', 
                mime='text/csv'
            )
        
        with dl_col2:
            if os.path.exists("rf_model.pkl"):
                with open("rf_model.pkl", "rb") as f:
                    st.download_button(label="Download Model (.pkl)", data=f, file_name="rf_ids_model.pkl", mime="application/octet-stream")
        
        with dl_col3:
            if os.path.exists("encoders.pkl"):
                with open("encoders.pkl", "rb") as f:
                    st.download_button(label="Download Encoders (.pkl)", data=f, file_name="ids_encoders.pkl", mime="application/octet-stream")

        # --- TAHAP 5: DATA EXPLORER ---
        st.divider()
        st.subheader("Detail Penelusuran Log")
        
        # Popover Keterangan Kolom
        with st.popover("Lihat Keterangan Kolom"):
            st.markdown("""
            ### Panduan Kolom:
            * Identitas Unik (uid): ID unik sesi komunikasi.
            * IP Pengirim (id.orig_h): Alamat IP perangkat pengirim.
            * IP Tujuan (id.resp_h): Alamat IP server target.
            * Port Tujuan (id.resp_p): Nomor pintu layanan yang diakses.
            * Jenis Layanan (service): Protokol aplikasi (ssl, http, dll).
            * Status Koneksi (conn_state): Kondisi teknis akhir (SF, RSTR, SH).
            * Hasil Prediksi (label): Klasifikasi akhir AI.
            """)

        # Filter Interaktif
        choice = st.selectbox("Filter Status Traffic:", ["Semua", "Normal", "Port Scanning", "TLS DDoS"], key='filter_choice')
        display_df = df if choice == "Semua" else df[df['label'] == choice]
        
        # Alias Tampilan Dashboard
        view_df = display_df[export_features].copy()
        view_df.columns = ['Identitas Unik', 'IP Pengirim', 'IP Tujuan', 'Port Tujuan', 'Jenis Layanan', 'Status Koneksi', 'Hasil Prediksi']
        
        st.write(f"Menampilkan {len(view_df)} data ({choice})")
        st.dataframe(view_df.head(100), width="stretch")

    else:
        st.info("💡 Silakan klik tombol 'Mulai Latih Model AI' setelah preprocessing selesai.")

else:
    st.info("👋 Selamat Datang! Silakan upload file conn.log dan ssl.log di sidebar untuk memulai analisis.")