"""
Risk Scoring Service.
Calculates how dangerous each threat is based on hard facts only.

Formula:
  Risk Score = (CVSS x 0.45) + (Exploitability x 0.35) + (Recency x 0.20)

All components are normalized to 0-100 before weighting.
A threat with a high CVSS, known exploit, discovered today = score near 100.
"""

from datetime import datetime, timezone
from typing import Optional


def calculate_risk_score(
    cvss_score: Optional[float] = None,
    exploit_available: str = "unknown",
    description: str = "",
    regions: str = "",
    published_at: Optional[datetime] = None,
    nlp_confidence: Optional[float] = None,
) -> dict:
    """
    Calculate a risk score for a threat.

    Returns dict with:
        risk_score (0-100), confidence (0-1),
        is_mena_relevant (bool), and component breakdown.
    """

    # --- Component 1: CVSS Base Score (weight: 45%) ---
    # CVSS is 0-10, we scale to 0-100
    if cvss_score is not None:
        cvss_component = cvss_score * 10
        cvss_confidence = 1.0
    else:
        cvss_component = 50.0  # Unknown = assume medium
        cvss_confidence = 0.3

    # --- Component 2: Exploitability (weight: 35%) ---
    # A known exploit dramatically increases risk.
    # When exploit status is unknown, the NLP model's confidence acts as a
    # proxy: high confidence means the text reads like a real, dangerous
    # exploit scenario (attack patterns, TTPs detected), which justifies a
    # higher risk signal than the default floor.
    # Formula: exploit_component = 40 + (nlp_confidence - 0.5) * 100, clamped 40–90
    # Examples: nlp=0.50 → 40, nlp=0.70 → 60, nlp=0.85 → 75, nlp=1.00 → 90
    if exploit_available == "yes":
        exploit_component = 100.0
        exploit_confidence = 1.0
    elif exploit_available == "no":
        exploit_component = 10.0
        exploit_confidence = 0.9
    else:
        if nlp_confidence is not None and nlp_confidence > 0.5:
            boost = (nlp_confidence - 0.5) * 100.0
            exploit_component = min(90.0, 40.0 + boost)
        else:
            exploit_component = 40.0
        exploit_confidence = 0.3

    # --- Component 3: Recency (weight: 20%) ---
    # Newer threats are more urgent
    if published_at:
        if published_at.tzinfo is None:
            published_at = published_at.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - published_at).days
        if age_days <= 1:
            recency_component = 100.0
        elif age_days <= 7:
            recency_component = 80.0
        elif age_days <= 30:
            recency_component = 50.0
        elif age_days <= 90:
            recency_component = 25.0
        else:
            recency_component = 10.0
    else:
        recency_component = 60.0

    # --- Weighted Final Score ---
    risk_score = (
        cvss_component * 0.45
        + exploit_component * 0.35
        + recency_component * 0.20
    )

    # --- Overall Confidence ---
    confidence = cvss_confidence * 0.5 + exploit_confidence * 0.3 + 0.2

    # --- MENA relevance (kept for backward compatibility, not used in scoring) ---
    is_mena_relevant = False

    return {
        "risk_score": round(min(risk_score, 100.0), 1),
        "confidence": round(min(confidence, 1.0), 2),
        "is_mena_relevant": is_mena_relevant,
        "breakdown": {
            "cvss": round(cvss_component, 1),
            "exploitability": round(exploit_component, 1),
            "recency": round(recency_component, 1),
        },
    }


def severity_from_score(risk_score: float) -> str:
    """Convert a risk score (0-100) to a severity label."""
    if risk_score >= 90:
        return "critical"
    elif risk_score >= 70:
        return "high"
    elif risk_score >= 40:
        return "medium"
    elif risk_score >= 20:
        return "low"
    else:
        return "info"