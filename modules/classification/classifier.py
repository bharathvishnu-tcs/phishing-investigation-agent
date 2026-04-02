def classify(case):
    
    url_analysis = case.get("url_analysis", [])
    spoofing = case.get("spoofing", {})
    interaction = case.get("user_interaction", {})
    identity = case.get("identity", {})
    
    malicious_url = any(u.get("is_malicious") for u in url_analysis)
    spoofed = spoofing.get("is_spoofed", False)
    clicked = interaction.get("link_clicked", False)
    creds = identity.get("credentials_submitted", False)

    attachments = case.get("attachment_analysis", [])
    malicious_attachment = any(a.get("is_malicious") for a in attachments)

    classification = "False Positive"
    severity = "low"
    reasons = []
    

    if creds:
        classification = "Account Compromise"
        severity = "critical"
        reasons.append("User submitted credentials to malicious site")
    
    elif clicked and malicious_url:
        classification = "Phishing Incident"
        severity = "high"
        reasons.append("User clicked malicious phishing link")
    
    elif malicious_url or spoofed:
        classification = "Attempted Phishing"
        severity = "medium"
        reasons.append("Phishing indicators detected but no interaction")
    
    elif malicious_attachment:
        classification = "Malware Phishing"
        severity = "high"
        reasons.append("Malicious attachment detected")
    
    else:
        classification = "False Positive"
        severity = "low"
        reasons.append("No strong malicious indicators")

    #adjusting severity wrt risk_level
    risk_score = case.get("risk",{}).get("score",0)

    if severity == "medium" and risk_score >= 70:
        severity = "high"
    elif severiy == "high" and risk_score >= 85:
        severity = "critical"
    
    case["decision"] = {
        "classification": classification,
        "severity": severity,
        "reasons": reasons
    }
    
    return case