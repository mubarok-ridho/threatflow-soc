import os
from dotenv import load_dotenv

load_dotenv()

# ── Gemini ──────────────────────────────────────────
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = "gemini-2.0-flash"
# ── Model Paths ──────────────────────────────────────
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR    = os.path.join(BASE_DIR, "models")

GROQ_API_KEY = os.getenv("GROQ_API_KEY")

XGBOOST_PATH = os.path.join(MODEL_DIR, "xgboost_model.pkl")
CNN_PATH     = os.path.join(MODEL_DIR, "cnn_model.keras")
RESNET_PATH  = os.path.join(MODEL_DIR, "resnet_best.keras")
SCALER_PATH  = os.path.join(MODEL_DIR, "scaler.pkl")

# ── Ensemble Weights ─────────────────────────────────
WEIGHT_XGBOOST = 0.50
WEIGHT_RESNET  = 0.30
WEIGHT_CNN     = 0.20

# ── Threshold ────────────────────────────────────────
ANOMALY_THRESHOLD = 0.35

# ── Feature Columns ──────────────────────────────────
FEATURE_COLS = [
    'Fwd Header Length', 'Destination Port', 'Flow Duration',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Fwd Packet Length Std', 'Bwd Packet Length Std',
    'Flow Bytes/s', 'Flow Packets/s', 'Total Fwd Packets',
    'Total Backward Packets', 'Init_Win_bytes_forward',
    'Init_Win_bytes_backward', 'Avg Fwd Segment Size',
    'Avg Bwd Segment Size', 'Average Packet Size',
    'Packet Length Mean', 'Fwd IAT Std', 'Bwd IAT Std',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max',
    'Fwd IAT Mean', 'Bwd IAT Mean', 'ACK Flag Count',
    'SYN Flag Count', 'FIN Flag Count', 'PSH Flag Count',
    'URG Flag Count', 'Subflow Fwd Packets', 'Subflow Bwd Packets',
    'Subflow Fwd Bytes', 'Subflow Bwd Bytes', 'Fwd Packets/s',
    'Bwd Packets/s', 'Down/Up Ratio'
]