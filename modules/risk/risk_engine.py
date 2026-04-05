from app.config import *
def calculate_risk(case):
    score = 0
    reasons = []

    if any(u.get("is_malicious") for u in case.get("url_analysis",[])):
        score += RISK_URL
        reasons.append("Malicious URL detected")

    spoof_score = case.get("spoofing", {}).get("spoof_score", 0)

    if spoof_score > 0:
        score += spoof_score * 5
        reasons.append("Sender spoofing / typosquatting indicators detected")
    
    # Email authentication risk (SPF/DKIM/DMARC weighted)
    auth_risk = case.get("header_analysis", {}).get("auth_risk", 0)
    if auth_risk > 0:
        score += auth_risk
        reasons.append("SPF/DKIM/DMARC authentication issues detected")

    if any(u.get("is_new_domain") for u in case.get("enrichment",{}).get("urls",[])):
        score+=RISK_NEW_DOMAIN
        reasons.append("New domain detected")
    
    if case.get("identity",{}).get("credentials_submitted"):
        score+=RISK_IDENTITY
        reasons.append("Credentials submitted")
    
    if any(a.get("is_malicious") for a in case.get("attachment_analysis",[])):
        score+=RISK_ATTACHMENT
        reasons.append("Malicious attachment detected")
    
    case["risk"] = {
        "score": min(score,100),
        "level": get_risk_level(score),
        "reasons": reasons
    }

    return case


def get_risk_level(score):
    if score>=80:
        return "Critical"
    elif score>=60:
        return "High"
    elif score>=30:
        return "Medium"
    else:
        return "Low"

    