import json
from groq import Groq
from config import GROQ_API_KEY

client = Groq(api_key=GROQ_API_KEY)


def explain_anomaly(prediction: dict, raw_input: dict) -> str:

    prompt = f"""
You are an experienced SOC (Security Operation Center) analyst assistant.
Analyze the network anomaly detection results from our ML ensemble system.
Provide explanation in BOTH Bahasa Indonesia and English.

IMPORTANT RULES:
- Base your analysis ONLY on the data and scores provided below
- Do NOT fabricate attack types not supported by the data
- Reference actual values from the input data
- Be specific and actionable

=== ML ENSEMBLE DETECTION RESULTS ===
Status          : {prediction['status']}
Ensemble Score  : {prediction['ensemble_score']} (0=normal, 1=definitely anomaly)
XGBoost Score   : {prediction['xgboost_score']}
CNN Score       : {prediction['cnn_score']}
ResNet Score    : {prediction['resnet_score']}
Confidence      : {prediction['confidence']}

=== KEY INDICATORS ===
SYN_Flag_Count      : {raw_input.get('SYN_Flag_Count', 0)}
Flow_Packets_s      : {raw_input.get('Flow_Packets_s', 0)}
Flow_Bytes_s        : {raw_input.get('Flow_Bytes_s', 0)}
Total_Fwd_Packets   : {raw_input.get('Total_Fwd_Packets', 0)}
Total_Bwd_Packets   : {raw_input.get('Total_Backward_Packets', 0)}
Destination_Port    : {raw_input.get('Destination_Port', 0)}

Respond ONLY with this exact JSON format, no preamble, no backticks:
result = [
  {{
    "threat_level"      : "LOW/MEDIUM/HIGH/CRITICAL",
    "attack_type_id"    : "nama serangan dalam Bahasa Indonesia",
    "attack_type_en"    : "attack name in English",
    "mitre_technique"   : "MITRE ATT&CK technique ID and name",
    "summary_id"        : "ringkasan berdasarkan data aktual",
    "summary_en"        : "summary based on actual data",
    "impact_id"         : "potensi dampak dalam Bahasa Indonesia",
    "impact_en"         : "potential impact in English",
    "recommendation_id" : "langkah mitigasi spesifik Bahasa Indonesia",
    "recommendation_en" : "specific mitigation steps in English",
    "data_evidence"     : "nilai spesifik dari data yang mendukung kesimpulan"
  }}
]
"""

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=2048,
        )

        raw_text = response.choices[0].message.content.strip()

        # Bersihkan backtick kalau ada
        if raw_text.startswith("```"):
            raw_text = raw_text.split("```")[1]
            if raw_text.startswith("json"):
                raw_text = raw_text[4:]

        local_vars = {}
        exec(raw_text, {}, local_vars)
        result = local_vars.get("result", [])

        if result:
            r = result[0]
            explanation = (
                f"🚨 [{r.get('threat_level')}] "
                f"{r.get('attack_type_id')} / {r.get('attack_type_en')}\n\n"
                f"📌 MITRE: {r.get('mitre_technique')}\n\n"
                f"📋 [ID] {r.get('summary_id')}\n"
                f"📋 [EN] {r.get('summary_en')}\n\n"
                f"💥 [ID] {r.get('impact_id')}\n"
                f"💥 [EN] {r.get('impact_en')}\n\n"
                f"🛡️ [ID] {r.get('recommendation_id')}\n"
                f"🛡️ [EN] {r.get('recommendation_en')}\n\n"
                f"🔍 Evidence: {r.get('data_evidence')}"
            )
            return explanation

    except Exception as e:
        return f"⚠️ LLM explanation unavailable: {str(e)}"

    return "⚠️ Tidak dapat menghasilkan penjelasan."