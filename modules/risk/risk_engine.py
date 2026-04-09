import logging

logger = logging.getLogger(__name__)

# =========================
# WEIGHTS (Balanced)
# =========================
WEIGHTS = {
    "signals": 0.35,
    "behavior": 0.35,
    "attack_chain": 0.20,
    "confidence": 0.10,
}


# =========================
# SIGNAL SCORE (0–100)
# =========================
def _score_signals(case):
    score = 0

    # Header (SPF/DKIM/DMARC)
    header_score = case.get("header_analysis", {}).get("score", 0)
    score = max(score, header_score)

    # URL
    for u in case.get("url_click_evidence", []):
        score = max(score, u.get("analysis", {}).get("score", 0) * 10)

    # Spoofing
    spoof_score = case.get("spoofing_evidence", {}).get("spoof_score", 0)
    score = max(score, spoof_score * 10)

    # Attachment
    for a in case.get("attachment_evidence", []):
        score = max(score, a.get("score", 0))

    # IOC
    if case.get("ioc_sweep", {}).get("matches_found"):
        score = max(score, 80)

    return min(score, 100)


# =========================
# BEHAVIOR SCORE (0–100)
# =========================
def _score_behavior(case):
    stages = case.get("decision", {}).get("attack_stages", {})
    score = 0

    if stages.get("interaction"):
        score += 20

    if stages.get("execution"):
        score += 10

    if stages.get("credential_access"):
        score += 25

    if stages.get("lateral_movement"):
        score += 15

    if stages.get("persistence"):
        score += 20

    if stages.get("exfiltration"):
        score += 30

    return min(score, 100)


# =========================
# ATTACK CHAIN SCORE (0–100)
# =========================
def _score_attack_chain(case):
    chain = case.get("decision", {}).get("attack_chain", [])

    score = len(chain) * 10

    if "Credential Theft" in chain:
        score += 15

    if "Persistence" in chain:
        score += 20

    if "Data Exfiltration" in chain:
        score += 25

    return min(score, 100)


# =========================
# LLM CONFIDENCE SCORE (0–100)
# =========================
def _score_confidence(case):
    confidence = case.get("decision", {}).get("confidence", 0.5)
    return confidence * 100


# =========================
# FINAL RISK CALCULATION
# =========================
def calculate_risk(case):

    components = {
        "signals": _score_signals(case),
        "behavior": _score_behavior(case),
        "attack_chain": _score_attack_chain(case),
        "confidence": _score_confidence(case),
    }

    # Weighted score
    final_score = sum(components[k] * WEIGHTS[k] for k in components)
    final_score = min(round(final_score), 100)

    # =========================
    # SEVERITY MAPPING
    # =========================
    if final_score >= 90:
        level = "Critical"
    elif final_score >= 70:
        level = "High"
    elif final_score >= 40:
        level = "Medium"
    else:
        level = "Low"

    # =========================
    # OUTPUT
    # =========================
    case["risk"] = {
        "score": final_score,
        "level": level,
        "breakdown": components
    }

    logger.info(f"[RiskEngine] Score={final_score} Breakdown={components}")

    return case