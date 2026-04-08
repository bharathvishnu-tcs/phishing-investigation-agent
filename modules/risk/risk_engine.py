def calculate_risk(case):

    stages = case.get("decision", {}).get("attack_stages", {})

    score = 0
    reasons = []

    if stages.get("delivery"):
        score += 5
        reasons.append("Phishing email delivered")

    if stages.get("interaction"):
        score += 15
        reasons.append("User interacted with phishing content")

    if stages.get("execution"):
        score += 20
        reasons.append("Endpoint executed suspicious activity")

    if stages.get("credential_access"):
        score += 40
        reasons.append("Credentials potentially compromised")

    if stages.get("persistence"):
        score += 30
        reasons.append("Attacker persistence established")

    if stages.get("lateral_movement"):
        score += 25
        reasons.append("Suspicious login / impossible travel")

    if stages.get("exfiltration"):
        score += 50
        reasons.append("Potential data exfiltration")

    # Cap score
    score = min(score, 100)

    # Risk Levels
    if score >= 80:
        level = "Critical"
    elif score >= 60:
        level = "High"
    elif score >= 30:
        level = "Medium"
    else:
        level = "Low"

    case["risk"] = {
        "score": score,
        "level": level,
        "reasons": reasons
    }

    return case