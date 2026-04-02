import difflib

def domain_similarity(domain1,domain2):
    return difflib.SequenceMatcher(None, domain1,domain2).ratio()

def analyze_url(case):
    
    enriched_urls = case.get("enrichment", {}).get("urls", [])
    sender_domain = case.get("enrichment", {}).get("sender_domain", "")
    
    results = []
    
    for item in enriched_urls:
        url = item["url"]
        domain = item["domain"]
        keywords = item["keywords"]
        
        score = 0
        reasons = []

        if item.get("is_new_domain"):
            score+= 2
            reasons.append("Newly registered domain")
        
        if keywords:
            score += len(keywords)
            reasons.append("Suspicious keywords in URL")
        
        if sender_domain not in domain:
            score += 2
            reasons.append("Domain mismatch (possible phishing)")
        
        similarity = domain_similarity(domain,sender_domain) if sender_domain else 0
        if similarity > 0.6 and similarity < 1.0:
            score+=2
            reasons.append("Lookalike domain name")
        
        suspicious_tlds = ["xyz", "top", "click", "info"]
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            score += 1
            reasons.append("Suspicious TLD")
    
        if len(domain) > 25:
            score += 1
            reasons.append("Unusually long domain")
        

        if sender_domain and domain.replace("-", "") != sender_domain.replace("-", ""):
            score += 1
            reasons.append("Possible lookalike domain")
        
        results.append({
            "url": url,
            "domain": domain,
            "score": score,
            "reasons": reasons,
            "is_malicious": score >= 3
        })
    
    case["url_analysis"] = results
    
    return case