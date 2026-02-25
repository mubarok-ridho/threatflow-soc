import numpy as np
import joblib
from tensorflow import keras
from config import (
    XGBOOST_PATH, CNN_PATH, RESNET_PATH, SCALER_PATH,
    WEIGHT_XGBOOST, WEIGHT_CNN, WEIGHT_RESNET,
    ANOMALY_THRESHOLD, FEATURE_COLS
)


class EnsemblePredictor:

    def __init__(self):
        print("⏳ Loading models...")
        self.scaler  = joblib.load(SCALER_PATH)
        self.xgboost = joblib.load(XGBOOST_PATH)
        self.cnn     = keras.models.load_model(CNN_PATH)
        self.resnet  = keras.models.load_model(RESNET_PATH)
        print("✅ Semua model berhasil diload!")

    def _preprocess(self, raw: dict) -> np.ndarray:
        # Mapping: nama field API → nama kolom training
        field_map = {
            'Fwd_Header_Length'           : 'Fwd Header Length',
            'Destination_Port'            : 'Destination Port',
            'Flow_Duration'               : 'Flow Duration',
            'Total_Length_of_Fwd_Packets' : 'Total Length of Fwd Packets',
            'Total_Length_of_Bwd_Packets' : 'Total Length of Bwd Packets',
            'Fwd_Packet_Length_Std'       : 'Fwd Packet Length Std',
            'Bwd_Packet_Length_Std'       : 'Bwd Packet Length Std',
            'Flow_Bytes_s'                : 'Flow Bytes/s',
            'Flow_Packets_s'              : 'Flow Packets/s',
            'Total_Fwd_Packets'           : 'Total Fwd Packets',
            'Total_Backward_Packets'      : 'Total Backward Packets',
            'Init_Win_bytes_forward'      : 'Init_Win_bytes_forward',
            'Init_Win_bytes_backward'     : 'Init_Win_bytes_backward',
            'Avg_Fwd_Segment_Size'        : 'Avg Fwd Segment Size',
            'Avg_Bwd_Segment_Size'        : 'Avg Bwd Segment Size',
            'Average_Packet_Size'         : 'Average Packet Size',
            'Packet_Length_Mean'          : 'Packet Length Mean',
            'Fwd_IAT_Std'                 : 'Fwd IAT Std',
            'Bwd_IAT_Std'                 : 'Bwd IAT Std',
            'Flow_IAT_Mean'               : 'Flow IAT Mean',
            'Flow_IAT_Std'                : 'Flow IAT Std',
            'Flow_IAT_Max'                : 'Flow IAT Max',
            'Fwd_IAT_Mean'                : 'Fwd IAT Mean',
            'Bwd_IAT_Mean'                : 'Bwd IAT Mean',
            'ACK_Flag_Count'              : 'ACK Flag Count',
            'SYN_Flag_Count'              : 'SYN Flag Count',
            'FIN_Flag_Count'              : 'FIN Flag Count',
            'PSH_Flag_Count'              : 'PSH Flag Count',
            'URG_Flag_Count'              : 'URG Flag Count',
            'Subflow_Fwd_Packets'         : 'Subflow Fwd Packets',
            'Subflow_Bwd_Packets'         : 'Subflow Bwd Packets',
            'Subflow_Fwd_Bytes'           : 'Subflow Fwd Bytes',
            'Subflow_Bwd_Bytes'           : 'Subflow Bwd Bytes',
            'Fwd_Packets_s'               : 'Fwd Packets/s',
            'Bwd_Packets_s'               : 'Bwd Packets/s',
            'Down_Up_Ratio'               : 'Down/Up Ratio',
        }

        # Susun nilai sesuai urutan FEATURE_COLS
        ordered = []
        for col in FEATURE_COLS:
            for field, mapped in field_map.items():
                if mapped == col:
                    ordered.append(raw.get(field, 0.0))
                    break

        arr = np.array(ordered).reshape(1, -1)
        arr = self.scaler.transform(arr)
        # Tidak di-clip supaya nilai out-of-range bisa terdeteksi sebagai anomali
        return arr

    def _get_confidence(self, score: float) -> str:
        if score >= 0.85:
            return "HIGH"
        elif score >= 0.65:
            return "MEDIUM"
        return "LOW"

    def predict(self, raw: dict) -> dict:
        arr = self._preprocess(raw)

        xgb_score = float(self.xgboost.predict_proba(arr)[0][1])

        cnn_score = float(self.cnn.predict(
            arr.reshape(1, 3, 3, 4, 1), verbose=0
        )[0][0])

        resnet_score = float(self.resnet.predict(arr, verbose=0)[0][0])

        ensemble_score = (
            WEIGHT_XGBOOST * xgb_score +
            WEIGHT_CNN     * cnn_score +
            WEIGHT_RESNET  * resnet_score
        )

        is_anomaly = ensemble_score >= ANOMALY_THRESHOLD

        return {
            "status"            : "ANOMALI" if is_anomaly else "NORMAL",
            "ensemble_score"    : round(ensemble_score, 4),
            "xgboost_score"     : round(xgb_score, 4),
            "cnn_score"         : round(cnn_score, 4),
            "resnet_score"      : round(resnet_score, 4),
            "is_anomaly"        : is_anomaly,
            "confidence"        : self._get_confidence(ensemble_score),
            "gemini_explanation": None
        }


# Singleton
predictor = EnsemblePredictor()