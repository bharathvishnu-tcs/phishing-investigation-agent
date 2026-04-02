def analyze_attachments(case):
    
    attachments = case.get("email", {}).get("attachments", [])
    hashes = case.get("email", {}).get("attachment_hashes", [])
    
    results = []
    
    for i, file in enumerate(attachments):
        
        file_hash = hashes[i] if i < len(hashes) else None
        
        score = 0
        reasons = []
        
        if file.endswith((".exe", ".js", ".bat", ".vbs")):
            score += 3
            reasons.append("Executable attachment")
        
        elif file.endswith((".docm", ".xlsm")):
            score += 2
            reasons.append("Macro-enabled document")
        
        elif file.endswith(".pdf"):
            score += 1
            reasons.append("PDF (possible phishing lure)")
        
        # Fake hash reputation
        if file_hash and "abc" in file_hash:
            score += 3
            reasons.append("Known malicious hash (simulated)")
        
        results.append({
            "file_name": file,
            "hash": file_hash,
            "score": score,
            "is_malicious": score >= 3,
            "reasons": reasons
        })
    
    case["attachment_analysis"] = results
    
    return case
