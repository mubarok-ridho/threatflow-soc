from pydantic import BaseModel
from typing import Optional

# ── Input Schema ─────────────────────────────────────
class NetworkFlow(BaseModel):
    """
    Satu baris network flow dari Suricata EVE JSON
    Semua fitur yang dibutuhkan model
    """
    Fwd_Header_Length           : float
    Destination_Port            : float
    Flow_Duration               : float
    Total_Length_of_Fwd_Packets : float
    Total_Length_of_Bwd_Packets : float
    Fwd_Packet_Length_Std       : float
    Bwd_Packet_Length_Std       : float
    Flow_Bytes_s                : float
    Flow_Packets_s              : float
    Total_Fwd_Packets           : float
    Total_Backward_Packets      : float
    Init_Win_bytes_forward      : float
    Init_Win_bytes_backward     : float
    Avg_Fwd_Segment_Size        : float
    Avg_Bwd_Segment_Size        : float
    Average_Packet_Size         : float
    Packet_Length_Mean          : float
    Fwd_IAT_Std                 : float
    Bwd_IAT_Std                 : float
    Flow_IAT_Mean               : float
    Flow_IAT_Std                : float
    Flow_IAT_Max                : float
    Fwd_IAT_Mean                : float
    Bwd_IAT_Mean                : float
    ACK_Flag_Count              : float
    SYN_Flag_Count              : float
    FIN_Flag_Count              : float
    PSH_Flag_Count              : float
    URG_Flag_Count              : float
    Subflow_Fwd_Packets         : float
    Subflow_Bwd_Packets         : float
    Subflow_Fwd_Bytes           : float
    Subflow_Bwd_Bytes           : float
    Fwd_Packets_s               : float
    Bwd_Packets_s               : float
    Down_Up_Ratio               : float

# ── Output Schema ─────────────────────────────────────
class PredictionResult(BaseModel):
    """
    Hasil prediksi dari ensemble 3 model
    """
    status              : str           # "NORMAL" atau "ANOMALI"
    ensemble_score      : float         # 0.0 - 1.0
    xgboost_score       : float
    cnn_score           : float
    resnet_score        : float
    is_anomaly          : bool
    gemini_explanation  : Optional[str] # Penjelasan dari Gemini
    confidence          : str           # "LOW", "MEDIUM", "HIGH"