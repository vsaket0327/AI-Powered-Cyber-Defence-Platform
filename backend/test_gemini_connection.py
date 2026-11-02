from app.ai_security_analyzer import analyze_security_evidence

sample_evidence = {
    "indicator_type": "ip",
    "indicator": "8.8.8.8",
    "risk_score": 5,
    "risk_level": "low",
    "verdict": "no_malicious_detections",
    "threat_intelligence": {
        "available": True,
        "analysis_stats": {
            "malicious": 0,
            "suspicious": 0,
            "harmless": 10,
            "undetected": 5
        }
    }
}

try:
    result = analyze_security_evidence(sample_evidence)

    print("\nGEMINI CONNECTION SUCCESSFUL")
    print("\nAI SECURITY ANALYSIS:")
    print(result)

except Exception as exc:
    print("\nGEMINI CONNECTION FAILED")
    print(str(exc))