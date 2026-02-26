#!/usr/bin/env python3
"""
nfstream_to_ml.py
Capture network traffic langsung dari interface menggunakan NFStream,
extract fitur lengkap, lalu kirim ke EnsemblePredictor.

Cara pakai:
    python3 nfstream_to_ml.py
"""

import sys
import os
import json
import math
from datetime import datetime

PIPELINE_PATH = "/opt/threatflow-soc"
INTERFACE     = "ens160"
ANOMALY_LOG   = "/var/log/suricata/anomaly_detected_nf.log"

sys.path.insert(0, PIPELINE_PATH)
os.chdir(PIPELINE_PATH)

from nfstream import NFStreamer
from app.predictor import predictor
from app.gemini import explain_anomaly


def flow_to_features(flow):
    """Map NFStream flow object ke dict fitur model."""

    duration_us = float(flow.bidirectional_duration_ms) * 1000.0
    duration_s  = duration_us / 1_000_000 if duration_us > 0 else 1e-9

    bytes_fwd  = float(flow.src2dst_bytes)
    bytes_bwd  = float(flow.dst2src_bytes)
    pkts_fwd   = float(flow.src2dst_packets)
    pkts_bwd   = float(flow.dst2src_packets)
    total_bytes= bytes_fwd + bytes_bwd
    total_pkts = pkts_fwd + pkts_bwd

    avg_fwd_seg = bytes_fwd / pkts_fwd if pkts_fwd > 0 else 0.0
    avg_bwd_seg = bytes_bwd / pkts_bwd if pkts_bwd > 0 else 0.0
    avg_pkt     = total_bytes / total_pkts if total_pkts > 0 else 0.0

    # IAT (Inter-Arrival Time) — NFStream dengan statistical_analysis=True
    fwd_iat_mean = float(getattr(flow, 'src2dst_mean_ps', 0) or 0)
    fwd_iat_std  = float(getattr(flow, 'src2dst_stddev_ps', 0) or 0)
    bwd_iat_mean = float(getattr(flow, 'dst2src_mean_ps', 0) or 0)
    bwd_iat_std  = float(getattr(flow, 'dst2src_stddev_ps', 0) or 0)

    # Flow IAT
    flow_iat_mean = duration_us / total_pkts if total_pkts > 1 else 0.0
    flow_iat_std  = float(getattr(flow, 'bidirectional_stddev_ps', 0) or 0)
    flow_iat_max  = float(getattr(flow, 'bidirectional_max_ps', 0) or duration_us)

    # Packet length stats
    fwd_pkt_std = float(getattr(flow, 'src2dst_stddev_ps', 0) or 0)
    bwd_pkt_std = float(getattr(flow, 'dst2src_stddev_ps', 0) or 0)
    pkt_len_mean= avg_pkt

    # TCP flags
    syn = int(getattr(flow, 'bidirectional_syn_packets', 0) or 0)
    ack = int(getattr(flow, 'bidirectional_ack_packets', 0) or 0)
    fin = int(getattr(flow, 'bidirectional_fin_packets', 0) or 0)
    psh = int(getattr(flow, 'bidirectional_psh_packets', 0) or 0)
    urg = int(getattr(flow, 'bidirectional_urg_packets', 0) or 0)

    # Init window bytes
    init_win_fwd = float(getattr(flow, 'src2dst_init_win_bytes', 0) or 0)
    init_win_bwd = float(getattr(flow, 'dst2src_init_win_bytes', 0) or 0)

    down_up = bytes_bwd / bytes_fwd if bytes_fwd > 0 else 0.0

    features = {
        "Fwd_Header_Length"           : 20.0,
        "Destination_Port"            : float(flow.dst_port),
        "Flow_Duration"               : duration_us,
        "Total_Length_of_Fwd_Packets" : bytes_fwd,
        "Total_Length_of_Bwd_Packets" : bytes_bwd,
        "Fwd_Packet_Length_Std"       : fwd_pkt_std,
        "Bwd_Packet_Length_Std"       : bwd_pkt_std,
        "Flow_Bytes_s"                : total_bytes / duration_s,
        "Flow_Packets_s"              : total_pkts / duration_s,
        "Total_Fwd_Packets"           : pkts_fwd,
        "Total_Backward_Packets"      : pkts_bwd,
        "Init_Win_bytes_forward"      : init_win_fwd,
        "Init_Win_bytes_backward"     : init_win_bwd,
        "Avg_Fwd_Segment_Size"        : avg_fwd_seg,
        "Avg_Bwd_Segment_Size"        : avg_bwd_seg,
        "Average_Packet_Size"         : avg_pkt,
        "Packet_Length_Mean"          : pkt_len_mean,
        "Fwd_IAT_Std"                 : fwd_iat_std,
        "Bwd_IAT_Std"                 : bwd_iat_std,
        "Flow_IAT_Mean"               : flow_iat_mean,
        "Flow_IAT_Std"                : flow_iat_std,
        "Flow_IAT_Max"                : flow_iat_max,
        "Fwd_IAT_Mean"                : fwd_iat_mean,
        "Bwd_IAT_Mean"                : bwd_iat_mean,
        "ACK_Flag_Count"              : ack,
        "SYN_Flag_Count"              : syn,
        "FIN_Flag_Count"              : fin,
        "PSH_Flag_Count"              : psh,
        "URG_Flag_Count"              : urg,
        "Subflow_Fwd_Packets"         : pkts_fwd,
        "Subflow_Bwd_Packets"         : pkts_bwd,
        "Subflow_Fwd_Bytes"           : bytes_fwd,
        "Subflow_Bwd_Bytes"           : bytes_bwd,
        "Fwd_Packets_s"               : pkts_fwd / duration_s,
        "Bwd_Packets_s"               : pkts_bwd / duration_s,
        "Down_Up_Ratio"               : down_up,
    }

    # Sanitize inf/nan
    for k, v in features.items():
        if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
            features[k] = 0.0

    return features


def log_anomaly(flow, features, result):
    entry = {
        "timestamp" : datetime.now().isoformat(),
        "src_ip"    : flow.src_ip,
        "src_port"  : flow.src_port,
        "dest_ip"   : flow.dst_ip,
        "dest_port" : flow.dst_port,
        "proto"     : flow.protocol,
        "app_proto" : flow.application_name,
        "prediction": result,
    }
    with open(ANOMALY_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


def main():
    print("🚀 ThreatFlow SOC - NFStream → ML Integration")
    print(f"   Interface : {INTERFACE}")
    print(f"   Anomaly   : {ANOMALY_LOG}")
    print("-" * 60)

    count_total   = 0
    count_anomaly = 0

    streamer = NFStreamer(
        source=INTERFACE,
        statistical_analysis=True,   # aktifkan IAT, stddev, dll
        splt_analysis=0,
        n_dissections=20,
        idle_timeout=30,             # flow dianggap selesai setelah 30s idle
        active_timeout=300,          # max 5 menit per flow
    )

    print(f"📡 Capturing on {INTERFACE} ...")

    for flow in streamer:
        count_total += 1
        features = flow_to_features(flow)

        try:
            result = predictor.predict(features)
        except Exception as e:
            print(f"[ERROR] predict: {e}")
            continue

        src  = f"{flow.src_ip}:{flow.src_port}"
        dst  = f"{flow.dst_ip}:{flow.dst_port}"
        proto= flow.application_name or str(flow.protocol)

        if result["is_anomaly"]:
            count_anomaly += 1
            explanation = explain_anomaly(result, features)
            result["gemini_explanation"] = explanation
            log_anomaly(flow, features, result)
            print(f"\n🚨 ANOMALI | {src} → {dst} | {proto}")
            print(f"   Score={result['ensemble_score']} | Confidence={result['confidence']}")
            print(f"\n{explanation}")
            print("-" * 60)
        else:
            if count_total % 50 == 0:
                print(
                    f"✅ NORMAL | {src} → {dst} | {proto} | "
                    f"score={result['ensemble_score']} | "
                    f"total={count_total} anomali={count_anomaly}"
                )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n⛔ Stopped.")
