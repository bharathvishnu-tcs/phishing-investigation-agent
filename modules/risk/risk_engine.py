from app.config import *
def calculate_risk(case):
    score = 0
    reasons = []

    if any(u.get("is_malicious") for u in case.get("url_analysis",[])):
        score += RISK_URL
        reasons.append("Malicious URL detected")

    if case.get("spoofing",{}).get("is_spoofed"):
        score+= RISK_SPOOFING
        reasons.append("Spoofed sender detected")
    
    if case.get("header_analysis",{}).get("is_suspicious"):
        score+=RISK_HEADER
        reasons.append("Email Authentication failed")

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

    