import difflib

def analyze_spoofing(case):
    
    sender_email = case.get("email", {}).get("sender_email", "")
    sender_domain = case.get("enrichment", {}).get("sender_domain", "")
    
    spoof_score = 0
    reasons = []
    
    if sender_domain:
        #needs to be changed
        legit_domains = ["paypal.com", "microsoft.com", "google.com"]
        
        for legit in legit_domains:
            if sender_domain != legit:
                similarity = difflib.SequenceMatcher(None, sender_domain, legit).ratio()
                
                if similarity > 0.7:
                    spoof_score += 2
                    reasons.append(f"Possible impersonation of {legit}")
    
    if "support" in sender_email or "security" in sender_email:
        spoof_score += 1
        reasons.append("Generic sender name used")
    
    case["spoofing"] = {
        "spoof_score": spoof_score,
        "is_spoofed": spoof_score >= 2,
        "reasons": reasons
    }
    
    return case