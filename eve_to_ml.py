#!/usr/bin/env python3
"""
eve_to_ml.py
Baca EVE JSON Suricata secara real-time, extract features,
lalu kirim ke EnsemblePredictor dari threatflow-soc pipeline.

Cara pakai:
    python3 eve_to_ml.py
"""

import json
import time
import sys
import os
import math
from datetime import datetime

# ── Path ke pipeline kamu (sesuaikan setelah clone) ──────────────────
PIPELINE_PATH = "/opt/threatflow-soc"
EVE_JSON_PATH = "/var/log/suricata/eve.json"
ANOMALY_LOG   = "/var/log/suricata/anomaly_detected.log"

# Tambahkan path pipeline ke sys.path
sys.path.insert(0, PIPELINE_PATH)

# ── Import pipeline ───────────────────────────────────────────────────
from app.predictor import predictor  # EnsemblePredictor singleton


# ── Feature extractor dari EVE flow record ────────────────────────────
def extract_features(eve: dict) -> dict | None:
    """
    Map EVE JSON flow record → dict fitur yang dibutuhkan model.
    Return None kalau bukan event_type 'flow'.
    """
    if eve.get("event_type") != "flow":
        return None

    flow = eve.get("flow", {})
    tcp  = eve.get("tcp", {})

    # Durasi dalam microseconds (seperti CICFlowMeter)
    start_str = flow.get("start", "")
    end_str   = flow.get("end", "")
    duration_us = 0.0
    try:
        fmt = "%Y-%m-%dT%H:%M:%S.%f%z"
        t_start = datetime.strptime(start_str, fmt)
        t_end   = datetime.strptime(end_str, fmt)
        duration_us = (t_end - t_start).total_seconds() * 1_000_000
    except Exception:
        duration_us = float(flow.get("age", 0)) * 1_000_000

    duration_s = duration_us / 1_000_000 if duration_us > 0 else 1e-9

    # Bytes dan packets
    bytes_fwd  = float(flow.get("bytes_toserver", 0))
    bytes_bwd  = float(flow.get("bytes_toclient", 0))
    pkts_fwd   = float(flow.get("pkts_toserver", 0))
    pkts_bwd   = float(flow.get("pkts_toclient", 0))
    total_pkts = pkts_fwd + pkts_bwd
    total_bytes= bytes_fwd + bytes_bwd

    # Avg segment size
    avg_fwd_seg = bytes_fwd / pkts_fwd if pkts_fwd > 0 else 0.0
    avg_bwd_seg = bytes_bwd / pkts_bwd if pkts_bwd > 0 else 0.0
    avg_pkt     = total_bytes / total_pkts if total_pkts > 0 else 0.0

    # TCP flags — Suricata catat di tcp.tcp_flags (hex string)
    # Juga tersedia tcp_flags_ts (to server) dan tcp_flags_tc (to client)
    flags_ts = int(tcp.get("tcp_flags_ts", "0x00"), 16) if tcp else 0
    flags_tc = int(tcp.get("tcp_flags_tc", "0x00"), 16) if tcp else 0
    flags_all = flags_ts | flags_tc

    syn_flag = 1 if (flags_all & 0x02) else 0
    ack_flag = 1 if (flags_all & 0x10) else 0
    fin_flag = 1 if (flags_all & 0x01) else 0
    psh_flag = 1 if (flags_all & 0x08) else 0
    urg_flag = 1 if (flags_all & 0x20) else 0

    # Init window bytes — tersedia di tcp jika ada
    init_win_fwd = float(tcp.get("win", 0)) if tcp else 0.0
    init_win_bwd = 0.0

    # Down/Up ratio
    down_up = bytes_bwd / bytes_fwd if bytes_fwd > 0 else 0.0

    features = {
        "Fwd_Header_Length"           : 20.0,           # default TCP header
        "Destination_Port"            : float(eve.get("dest_port", 0)),
        "Flow_Duration"               : duration_us,
        "Total_Length_of_Fwd_Packets" : bytes_fwd,
        "Total_Length_of_Bwd_Packets" : bytes_bwd,
        "Fwd_Packet_Length_Std"       : 0.0,            # tidak tersedia langsung
        "Bwd_Packet_Length_Std"       : 0.0,
        "Flow_Bytes_s"                : total_bytes / duration_s,
        "Flow_Packets_s"              : total_pkts / duration_s,
        "Total_Fwd_Packets"           : pkts_fwd,
        "Total_Backward_Packets"      : pkts_bwd,
        "Init_Win_bytes_forward"      : init_win_fwd,
        "Init_Win_bytes_backward"     : init_win_bwd,
        "Avg_Fwd_Segment_Size"        : avg_fwd_seg,
        "Avg_Bwd_Segment_Size"        : avg_bwd_seg,
        "Average_Packet_Size"         : avg_pkt,
        "Packet_Length_Mean"          : avg_pkt,
        "Fwd_IAT_Std"                 : 0.0,
        "Bwd_IAT_Std"                 : 0.0,
        "Flow_IAT_Mean"               : duration_us / total_pkts if total_pkts > 1 else 0.0,
        "Flow_IAT_Std"                : 0.0,
        "Flow_IAT_Max"                : duration_us,
        "Fwd_IAT_Mean"                : duration_us / pkts_fwd if pkts_fwd > 1 else 0.0,
        "Bwd_IAT_Mean"                : duration_us / pkts_bwd if pkts_bwd > 1 else 0.0,
        "ACK_Flag_Count"              : ack_flag,
        "SYN_Flag_Count"              : syn_flag,
        "FIN_Flag_Count"              : fin_flag,
        "PSH_Flag_Count"              : psh_flag,
        "URG_Flag_Count"              : urg_flag,
        "Subflow_Fwd_Packets"         : pkts_fwd,
        "Subflow_Bwd_Packets"         : pkts_bwd,
        "Subflow_Fwd_Bytes"           : bytes_fwd,
        "Subflow_Bwd_Bytes"           : bytes_bwd,
        "Fwd_Packets_s"               : pkts_fwd / duration_s,
        "Bwd_Packets_s"               : pkts_bwd / duration_s,
        "Down_Up_Ratio"               : down_up,
    }

    # Sanitize: ganti inf/nan dengan 0
    for k, v in features.items():
        if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
            features[k] = 0.0

    return features


# ── Tail EVE JSON ─────────────────────────────────────────────────────
def follow_eve(path: str):
    """Generator: yield satu EVE record per baris secara real-time."""
    print(f"📡 Monitoring {path} ...")
    with open(path, "r") as f:
        f.seek(0, 2)  # seek ke akhir file (tail mode)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.05)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


# ── Log anomali ───────────────────────────────────────────────────────
def log_anomaly(eve: dict, result: dict):
    entry = {
        "timestamp"      : eve.get("timestamp"),
        "src_ip"         : eve.get("src_ip"),
        "src_port"       : eve.get("src_port"),
        "dest_ip"        : eve.get("dest_ip"),
        "dest_port"      : eve.get("dest_port"),
        "proto"          : eve.get("proto"),
        "app_proto"      : eve.get("app_proto"),
        "flow_id"        : eve.get("flow_id"),
        "prediction"     : result,
    }
    with open(ANOMALY_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


# ── Main ──────────────────────────────────────────────────────────────
def main():
    print("🚀 ThreatFlow SOC - EVE → ML Integration")
    print(f"   Pipeline : {PIPELINE_PATH}")
    print(f"   EVE log  : {EVE_JSON_PATH}")
    print(f"   Anomaly  : {ANOMALY_LOG}")
    print("-" * 60)

    count_total   = 0
    count_anomaly = 0

    for eve in follow_eve(EVE_JSON_PATH):
        features = extract_features(eve)
        if features is None:
            continue

        count_total += 1

        try:
            result = predictor.predict(features)
        except Exception as e:
            print(f"[ERROR] predict failed: {e}")
            continue

        status     = result["status"]
        score      = result["ensemble_score"]
        confidence = result["confidence"]
        is_anomaly = result["is_anomaly"]

        src  = f"{eve.get('src_ip')}:{eve.get('src_port')}"
        dst  = f"{eve.get('dest_ip')}:{eve.get('dest_port')}"
        proto= eve.get("proto", "?")
        ts   = eve.get("timestamp", "")

        if is_anomaly:
            count_anomaly += 1
            log_anomaly(eve, result)
            print(
                f"🚨 [{ts}] ANOMALI | {src} → {dst} | {proto} | "
                f"score={score} | confidence={confidence}"
            )
        else:
            # Print setiap 100 normal flow biar tidak spam
            if count_total % 100 == 0:
                print(
                    f"✅ [{ts}] NORMAL  | {src} → {dst} | {proto} | "
                    f"score={score} | total={count_total} anomali={count_anomaly}"
                )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n⛔ Stopped.")
