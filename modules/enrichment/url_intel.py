import difflib
from app.config import * 

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
            score+= NEW_DOMAIN_SCORE
            reasons.append("Newly registered domain")
        
        if keywords:
            score += len(keywords) * URL_KEYWORD_SCORE
            reasons.append("Suspicious keywords in URL")
        
        if sender_domain not in domain:
            score += DOMAIN_MISMATCH_SCORE
            reasons.append("Domain mismatch (possible phishing)")
        
        similarity = domain_similarity(domain,sender_domain) if sender_domain else 0
        if similarity > 0.6 and similarity < 1.0:
            score+=LOOKALIKE_DOMAIN_SCORE
            reasons.append("Lookalike domain name")
        
        if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
            score += URL_TLDS_SCORE
            reasons.append("Suspicious TLD")
    
        if len(domain) > 25:
            score += LONG_URL
            reasons.append("Unusually long domain")
        

        if sender_domain and domain.replace("-", "") != sender_domain.replace("-", ""):
            score += 1
            reasons.append("Possible lookalike domain")
        
        results.append({
            "url": url,
            "domain": domain,
            "score": score,
            "reasons": reasons,
            "is_malicious": URL_MALICIOUS_THRESHOLD
        })
    
    case["url_analysis"] = results
    
    return case