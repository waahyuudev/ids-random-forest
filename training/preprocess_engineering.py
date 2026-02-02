import pandas as pd
import io

def load_zeek_log(uploaded_file):
    """Membaca log Zeek dari objek file yang diupload Streamlit."""
    lines = uploaded_file.getvalue().decode("utf-8").splitlines()
    # Mencari header kolom pada baris #fields
    fields = [line.strip().split('\t')[1:] for line in lines if line.startswith('#fields')][0]
    # Mengambil data mentah tanpa tanda #
    data = "\n".join([line for line in lines if not line.startswith('#')])
    return pd.read_csv(io.StringIO(data), sep='\t', names=fields, na_values='-')

def process_logs(conn_file, ssl_file):
    """Mengolah conn.log dan ssl.log menjadi dataset terlabeli."""
    conn_df = load_zeek_log(conn_file)
    ssl_df = load_zeek_log(ssl_file)
    
    # Gabungkan data berdasarkan UID
    df = pd.merge(conn_df, ssl_df[['uid', 'established']], on='uid', how='left')
    
    # Data Cleaning & Feature Engineering
    df['duration'] = pd.to_numeric(df['duration'], errors='coerce').fillna(0)
    df['orig_bytes'] = pd.to_numeric(df['orig_bytes'], errors='coerce').fillna(0)
    df['resp_bytes'] = pd.to_numeric(df['resp_bytes'], errors='coerce').fillna(0)
    df['established'] = df['established'].fillna('F')
    
    # Logika Labeling Otomatis
    def labeling(row):
        if row['service'] == 'ssl' and row['established'] == 'F': 
            return 'TLS DDoS'
        elif row['conn_state'] in ['S0', 'REJ', 'RSTR', 'RSTRH']: 
            return 'Port Scanning'
        return 'Normal'
    
    df['label'] = df.apply(labeling, axis=1)
    return df