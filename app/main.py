from fastapi import FastAPI, HTTPException
from app.schemas import NetworkFlow, PredictionResult
from app.predictor import predictor
from app.gemini import explain_anomaly

app = FastAPI(
    title="SOC ML Pipeline",
    description="Sistem deteksi anomali jaringan menggunakan ensemble ML + Gemini AI",
    version="1.0.0"
)


@app.get("/")
def root():
    return {
        "status" : "online",
        "service": "SOC ML Pipeline",
        "models" : ["XGBoost", "1D CNN", "ResNet Tabular"],
        "llm"    : "Gemini 1.5 Flash"
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/predict", response_model=PredictionResult)
async def predict(flow: NetworkFlow):
    """
    Terima satu network flow, prediksi dengan ensemble,
    kalau anomali → kirim ke Gemini untuk penjelasan
    """
    try:
        # Convert pydantic model → dict
        raw = flow.model_dump()

        # Prediksi dengan ensemble
        result = predictor.predict(raw)

        # Kalau anomali → minta penjelasan Gemini
        if result["is_anomaly"]:
            result["gemini_explanation"] = explain_anomaly(result, raw)

        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/predict/batch")
async def predict_batch(flows: list[NetworkFlow]):
    """
    Terima banyak network flow sekaligus (dari Suricata stream)
    Hanya anomali yang dikirim ke Gemini
    """
    try:
        results = []
        for flow in flows:
            raw    = flow.model_dump()
            result = predictor.predict(raw)

            if result["is_anomaly"]:
                result["gemini_explanation"] = explain_anomaly(result, raw)

            results.append(result)

        # Ringkasan batch
        total    = len(results)
        anomali  = sum(1 for r in results if r["is_anomaly"])
        normal   = total - anomali

        return {
            "summary": {
                "total"  : total,
                "normal" : normal,
                "anomali": anomali,
            },
            "results": results
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))