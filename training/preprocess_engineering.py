import pandas as pd
import io

def load_zeek_log(uploaded_file):
    """Membaca log Zeek dari objek file yang diupload dengan handling baris bermasalah."""
    # Decode dan ambil baris
    content = uploaded_file.getvalue().decode("utf-8")
    lines = content.splitlines()
    
    # Mencari header kolom pada baris #fields
    # Zeek fields line looks like: #fields\ts_ip\td_ip...
    fields_line = [line for line in lines if line.startswith('#fields')]
    if not fields_line:
        raise ValueError("Log file does not contain a #fields header.")
    
    # Split by tab and skip the first element (#fields)
    fields = fields_line[0].strip().split('\t')[1:]
    
    # Ambil data mentah tanpa baris yang diawali '#' (metadata)
    data_lines = [line for line in lines if not line.startswith('#')]
    data = "\n".join(data_lines)
    
    # Gunakan engine='python' dan on_bad_lines untuk stabilitas
    return pd.read_csv(
        io.StringIO(data), 
        sep='\t', 
        names=fields, 
        na_values='-', 
        engine='python',
        on_bad_lines='warn', # Lewati baris jika kolom tidak sesuai (seperti line 46)
        index_col=False      # Mencegah kolom pertama dianggap index jika ada extra tab
    )

def process_logs(conn_file, ssl_file):
    """Mengolah conn.log dan ssl.log menjadi dataset terlabeli."""
    conn_df = load_zeek_log(conn_file)
    ssl_df = load_zeek_log(ssl_file)
    
    # Pastikan 'uid' ada di kedua dataframe sebelum merging
    if 'uid' not in conn_df.columns or 'uid' not in ssl_df.columns:
        # Debugging: print columns if merge fails
        print("Conn Columns:", conn_df.columns)
        print("SSL Columns:", ssl_df.columns)
        return pd.DataFrame() # Return empty or handle error

    # Gabungkan data berdasarkan UID
    df = pd.merge(conn_df, ssl_df[['uid', 'established']], on='uid', how='left')
    
    # Data Cleaning & Feature Engineering
    # Menggunakan to_numeric agar string '-' atau whitespace tidak merusak model
    cols_to_fix = ['duration', 'orig_bytes', 'resp_bytes']
    for col in cols_to_fix:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
    
    # Pastikan kolom established ada (hasil merge)
    if 'established' in df.columns:
        df['established'] = df['established'].fillna('F')
    else:
        df['established'] = 'F'
    
    # Logika Labeling Otomatis
    def labeling(row):
        # Gunakan .get() atau check existence untuk safety
        service = row.get('service', '')
        established = row.get('established', 'F')
        conn_state = row.get('conn_state', '')

        if service == 'ssl' and established == 'F': 
            return 'TLS DDoS'
        elif conn_state in ['S0', 'REJ', 'RSTR', 'RSTRH']: 
            return 'Port Scanning'
        return 'Normal'
    
    df['label'] = df.apply(labeling, axis=1)
    return df