
from typing import Any


def calculate_risk(
    threat_intel: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Calculate a project-defined risk score from VirusTotal statistics.

    This heuristic is not a probability that an indicator is malicious.
    """

    if not threat_intel or not threat_intel.get("available"):
        return {
            "score": None,
            "risk_level": "unknown",
            "verdict": "unknown",
            "explanation": (
                "Threat-intelligence data is unavailable. "
                "A reliable risk score cannot be calculated."
            ),
        }

    stats = threat_intel.get("analysis_stats") or {}

    malicious = max(0, int(stats.get("malicious", 0)))
    suspicious = max(0, int(stats.get("suspicious", 0)))
    harmless = max(0, int(stats.get("harmless", 0)))
    undetected = max(0, int(stats.get("undetected", 0)))
    timeout = max(0, int(stats.get("timeout", 0)))
    confirmed_timeout = max(
        0, int(stats.get("confirmed-timeout", 0))
    )

    total = (
        malicious
        + suspicious
        + harmless
        + undetected
        + timeout
        + confirmed_timeout
    )

    if total == 0:
        return {
            "score": None,
            "risk_level": "unknown",
            "verdict": "unknown",
            "explanation": (
                "No usable analysis statistics were returned."
            ),
        }

    detection_ratio = (
        0.70 * malicious / total
        + 0.20 * suspicious / total
    )

    malicious_weight = 30 * min(malicious, 5) / 5
    suspicious_weight = 10 * min(suspicious, 5) / 5

    score = round(
        100 * detection_ratio
        + malicious_weight
        + suspicious_weight
    )

    score = max(0, min(100, score))

    if score >= 80:
        risk_level = "critical"
    elif score >= 50:
        risk_level = "high"
    elif score >= 20:
        risk_level = "medium"
    else:
        risk_level = "low"

    if malicious >= 5:
        verdict = "malicious"
    elif malicious >= 2 or suspicious > 0:
        verdict = "suspicious"
    elif malicious == 1:
        verdict = "needs_review"
    else:
        verdict = "no_malicious_detections"

    explanation = (
        f"Risk score: {score}/100 ({risk_level}). "
        f"Analysis included {malicious} malicious, "
        f"{suspicious} suspicious, {harmless} harmless, "
        f"{undetected} undetected, {timeout} timeout, "
        f"and {confirmed_timeout} confirmed-timeout results. "
        "The score is a project-defined heuristic, "
        "not a probability of malicious activity."
    )

    return {
        "score": score,
        "risk_level": risk_level,
        "verdict": verdict,
        "explanation": explanation,
    }