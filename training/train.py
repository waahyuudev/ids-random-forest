import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split

def train_rf_model(df):
    """Melatih model Random Forest dan menghitung metrik performa."""
    features = ['duration', 'orig_bytes', 'resp_bytes', 'orig_pkts', 'resp_pkts', 'proto', 'service', 'conn_state']
    X = df[features].fillna(0)
    y = df['label']
    
    # Encoding fitur kategorikal
    encoders = {}
    for col in ['proto', 'service', 'conn_state']:
        le = LabelEncoder()
        X[col] = le.fit_transform(X[col].astype(str))
        encoders[col] = le
    
    # Split data (80% latih, 20% uji) untuk mendapatkan metrik yang objektif
    # Menggunakan stratify agar pembagian kelas (Normal vs Serangan) tetap seimbang
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y if len(y.unique()) > 1 else None
    )

    # Pelatihan Model
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    # Prediksi pada data uji untuk evaluasi
    y_pred = model.predict(X_test)
    
    # Hitung Metrik (Weighted average digunakan karena jumlah data normal & serangan tidak seimbang)
    metrics = {
        'accuracy': accuracy_score(y_test, y_pred),
        'precision': precision_score(y_test, y_pred, average='weighted', zero_division=0),
        'recall': recall_score(y_test, y_pred, average='weighted', zero_division=0),
        'f1': f1_score(y_test, y_pred, average='weighted', zero_division=0)
    }
    
    # Simpan model dan encoders
    joblib.dump(model, 'rf_model.pkl')
    joblib.dump(encoders, 'encoders.pkl')
    
    return model, features, model.feature_importances_, metrics