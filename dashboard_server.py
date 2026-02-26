#!/usr/bin/env python3
"""
dashboard_server.py
FastAPI server dengan WebSocket untuk SOC dashboard realtime.
Jalankan: uvicorn dashboard_server:app --host 0.0.0.0 --port 8000
"""

import sys, os, json, math, asyncio
from datetime import datetime
from collections import deque
from typing import List

PIPELINE_PATH = "/opt/threatflow-soc"
INTERFACE     = "ens160"
ANOMALY_LOG   = "/var/log/suricata/anomaly_detected_nf.log"

sys.path.insert(0, PIPELINE_PATH)
os.chdir(PIPELINE_PATH)

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from nfstream import NFStreamer
from app.predictor import predictor
from app.gemini import explain_anomaly

app = FastAPI(title="ThreatFlow SOC Dashboard")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── State global ──────────────────────────────────────────────────────
recent_events  = deque(maxlen=200)   # semua event (normal + anomali)
recent_anomaly = deque(maxlen=50)    # anomali saja
stats = {
    "total_flows"  : 0,
    "total_anomaly": 0,
    "total_normal" : 0,
    "high"         : 0,
    "medium"       : 0,
    "low"          : 0,
}
clients: List[WebSocket] = []


# ── Feature extraction ────────────────────────────────────────────────
def flow_to_features(flow):
    duration_us = float(flow.bidirectional_duration_ms) * 1000.0
    duration_s  = duration_us / 1_000_000 if duration_us > 0 else 1e-9
    bytes_fwd   = float(flow.src2dst_bytes)
    bytes_bwd   = float(flow.dst2src_bytes)
    pkts_fwd    = float(flow.src2dst_packets)
    pkts_bwd    = float(flow.dst2src_packets)
    total_bytes = bytes_fwd + bytes_bwd
    total_pkts  = pkts_fwd + pkts_bwd

    features = {
        "Fwd_Header_Length"           : 20.0,
        "Destination_Port"            : float(flow.dst_port),
        "Flow_Duration"               : duration_us,
        "Total_Length_of_Fwd_Packets" : bytes_fwd,
        "Total_Length_of_Bwd_Packets" : bytes_bwd,
        "Fwd_Packet_Length_Std"       : float(getattr(flow, 'src2dst_stddev_ps', 0) or 0),
        "Bwd_Packet_Length_Std"       : float(getattr(flow, 'dst2src_stddev_ps', 0) or 0),
        "Flow_Bytes_s"                : total_bytes / duration_s,
        "Flow_Packets_s"              : total_pkts / duration_s,
        "Total_Fwd_Packets"           : pkts_fwd,
        "Total_Backward_Packets"      : pkts_bwd,
        "Init_Win_bytes_forward"      : float(getattr(flow, 'src2dst_init_win_bytes', 0) or 0),
        "Init_Win_bytes_backward"     : float(getattr(flow, 'dst2src_init_win_bytes', 0) or 0),
        "Avg_Fwd_Segment_Size"        : bytes_fwd / pkts_fwd if pkts_fwd > 0 else 0.0,
        "Avg_Bwd_Segment_Size"        : bytes_bwd / pkts_bwd if pkts_bwd > 0 else 0.0,
        "Average_Packet_Size"         : total_bytes / total_pkts if total_pkts > 0 else 0.0,
        "Packet_Length_Mean"          : total_bytes / total_pkts if total_pkts > 0 else 0.0,
        "Fwd_IAT_Std"                 : float(getattr(flow, 'src2dst_stddev_ps', 0) or 0),
        "Bwd_IAT_Std"                 : float(getattr(flow, 'dst2src_stddev_ps', 0) or 0),
        "Flow_IAT_Mean"               : duration_us / total_pkts if total_pkts > 1 else 0.0,
        "Flow_IAT_Std"                : float(getattr(flow, 'bidirectional_stddev_ps', 0) or 0),
        "Flow_IAT_Max"                : float(getattr(flow, 'bidirectional_max_ps', 0) or duration_us),
        "Fwd_IAT_Mean"                : float(getattr(flow, 'src2dst_mean_ps', 0) or 0),
        "Bwd_IAT_Mean"                : float(getattr(flow, 'dst2src_mean_ps', 0) or 0),
        "ACK_Flag_Count"              : int(getattr(flow, 'bidirectional_ack_packets', 0) or 0),
        "SYN_Flag_Count"              : int(getattr(flow, 'bidirectional_syn_packets', 0) or 0),
        "FIN_Flag_Count"              : int(getattr(flow, 'bidirectional_fin_packets', 0) or 0),
        "PSH_Flag_Count"              : int(getattr(flow, 'bidirectional_psh_packets', 0) or 0),
        "URG_Flag_Count"              : int(getattr(flow, 'bidirectional_urg_packets', 0) or 0),
        "Subflow_Fwd_Packets"         : pkts_fwd,
        "Subflow_Bwd_Packets"         : pkts_bwd,
        "Subflow_Fwd_Bytes"           : bytes_fwd,
        "Subflow_Bwd_Bytes"           : bytes_bwd,
        "Fwd_Packets_s"               : pkts_fwd / duration_s,
        "Bwd_Packets_s"               : pkts_bwd / duration_s,
        "Down_Up_Ratio"               : bytes_bwd / bytes_fwd if bytes_fwd > 0 else 0.0,
    }
    for k, v in features.items():
        if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
            features[k] = 0.0
    return features


# ── Broadcast ke semua WebSocket client ──────────────────────────────
async def broadcast(message: dict):
    disconnected = []
    for ws in clients:
        try:
            await ws.send_json(message)
        except:
            disconnected.append(ws)
    for ws in disconnected:
        clients.remove(ws)


# ── Background task: NFStream capture ────────────────────────────────
async def capture_loop():
    loop = asyncio.get_event_loop()

    def run_nfstream():
        streamer = NFStreamer(
            source=INTERFACE,
            statistical_analysis=True,
            splt_analysis=0,
            n_dissections=20,
            idle_timeout=30,
            active_timeout=300,
        )
        for flow in streamer:
            features = flow_to_features(flow)
            try:
                result = predictor.predict(features)
            except Exception as e:
                continue

            stats["total_flows"] += 1
            is_anomaly = result["is_anomaly"]

            event = {
                "type"       : "anomaly" if is_anomaly else "normal",
                "timestamp"  : datetime.now().isoformat(),
                "src_ip"     : flow.src_ip,
                "src_port"   : flow.src_port,
                "dst_ip"     : flow.dst_ip,
                "dst_port"   : flow.dst_port,
                "proto"      : flow.application_name or str(flow.protocol),
                "score"      : result["ensemble_score"],
                "confidence" : result["confidence"],
                "xgb_score"  : result["xgboost_score"],
                "cnn_score"  : result["cnn_score"],
                "resnet_score": result["resnet_score"],
                "explanation": None,
                "stats"      : dict(stats),
            }

            if is_anomaly:
                stats["total_anomaly"] += 1
                conf = result["confidence"]
                if conf == "HIGH":   stats["high"] += 1
                elif conf == "MEDIUM": stats["medium"] += 1
                else: stats["low"] += 1

                try:
                    explanation = explain_anomaly(result, features)
                    event["explanation"] = explanation
                except:
                    event["explanation"] = "⚠️ LLM explanation unavailable"

                # Log ke file
                with open(ANOMALY_LOG, "a") as f:
                    f.write(json.dumps(event) + "\n")

                recent_anomaly.appendleft(event)
            else:
                stats["total_normal"] += 1

            recent_events.appendleft(event)
            event["stats"] = dict(stats)

            asyncio.run_coroutine_threadsafe(broadcast(event), loop)

    await loop.run_in_executor(None, run_nfstream)


@app.on_event("startup")
async def startup():
    asyncio.create_task(capture_loop())


# ── REST endpoints ────────────────────────────────────────────────────
@app.get("/api/stats")
def get_stats():
    return stats

@app.get("/api/events")
def get_events(limit: int = 50):
    return list(recent_events)[:limit]

@app.get("/api/anomalies")
def get_anomalies(limit: int = 20):
    return list(recent_anomaly)[:limit]


# ── WebSocket endpoint ────────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    clients.append(websocket)
    # Kirim state awal
    await websocket.send_json({
        "type"     : "init",
        "stats"    : dict(stats),
        "events"   : list(recent_events)[:50],
        "anomalies": list(recent_anomaly)[:20],
    })
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        clients.remove(websocket)


# ── Dashboard HTML ────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def dashboard():
    return open("/opt/threatflow-soc/dashboard.html").read()
