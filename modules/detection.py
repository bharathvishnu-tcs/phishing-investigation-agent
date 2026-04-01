def detect_phishing(email):
    reasons= []

    if email.get("spf_result") == "fail":
        reasons.append("SPF failed")
    
    if email.get("urls"):
        reasons.append("Lookalike domain detected")
    if email.get("attachment",{}).get("exists"):
        reasons.append("Attachment present")
    return reasons