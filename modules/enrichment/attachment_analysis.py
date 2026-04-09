from app.config import *
def analyze_attachments(case):
    
    attachments = case.get("email_evidence").get("attachments")
    hashes = case.get("email_evidence").get("attachment_hashes")
    results = []
    
    for i in range(len(attachments)):
        file_hash = hashes[i] if i < len(hashes) else None
        
        score = 0
        reasons = []

        file_name = attachments[i].lower()
        
        if file_name.endswith((".exe", ".js", ".bat", ".vbs", ".scr", ".ps1")):
            score += ATTACH_EXECUTABLE_SCORE
            reasons.append("Executable attachment")
        
        elif file_name.endswith((".docm", ".xlsm", ".pptm")):
            score += ATTACH_MACRO_SCORE
            reasons.append("Macro-enabled document")
        elif file_name.endswith((".zip", ".rar", ".7z")):
            score += ATTACH_ARCHIVE_SCORE
            reasons.append("Compressed archive attachment")
        elif file_name.endswith(".pdf"):
            score += ATTACH_PDF_SCORE
            reasons.append("PDF (possible phishing lure)")
        
        if file_name.count(".") > 1:
            score += ATTACH_DOUBLE_EXT_SCORE
            reasons.append("Suspicious double extension")
                
        # Fake hash reputation
        if file_hash and "abc" in file_hash.lower():
            score += ATTACH_HASH_REPUTATION_SCORE
            reasons.append("Known malicious hash (simulated)")
        
        results.append({
            "file_name": file_name,
            "hash": file_hash,
            "score": score,
            "reasons": reasons,
            "is_malicious": score >= ATTACH_MALICIOUS_THRESHOLD
        })

    case["attachment_evidence"] = results
    return case
