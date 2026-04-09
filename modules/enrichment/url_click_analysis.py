import difflib
from app.config import * 
from utils.helper import extract_domain, find_suspicious_keywords, simulate_domain_age

import json

def ingest_url_click_log(path: str) -> dict:
    with open(path, "r") as f:
        return json.load(f)
    
def add_url_click_evidence(case: dict, log: dict) -> dict:
    case.setdefault("url_click_evidence").append({
        "url": log.get("Url"),
        "user": log.get("UserId"),
        "ip_address": log.get("IPAddress"),
        "device": log.get("DeviceName"),
        "click_action": log.get("ClickAction"),
        "clicked_through": log.get("IsClickedThrough"),
        "verdict": log.get("Verdict"),
        "threat_type": log.get("ThreatTypes"),
        "timestamp": log.get("TimeGenerated")
    })
    return case

def domain_similarity(domain1,domain2):
    return difflib.SequenceMatcher(None, domain1,domain2).ratio()

def analyze_url(case:dict) -> dict:
    """
    analyzes each clicked URL in a case for phishing risk by checking domain age,
    suspicious keywords, mismatches, lookalike domains, TLDs, and length
    enriches the case with a risk score and reasons for each URL

    """ 
    sender_domain = case.get("email_evidence", {}).get("sender_domain", "")
    raw_log = ingest_url_click_log("data/url_click_logs.json")
    raw_log = raw_log[case.get("log_index")]

    case["url_click_evidence"] = []
    case = add_url_click_evidence(case, raw_log)

    for item in case.get("url_click_evidence", []):
        url = item.get("url")
        domain = extract_domain(url)
        keywords = find_suspicious_keywords(url)
        #needs to be changed 
        domain_age = simulate_domain_age(domain)

        score = 0
        reasons = []

        if domain_age < 7:
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
    
        if len(domain) > 125:
            score += LONG_URL
            reasons.append("Unusually long domain")
        
        if sender_domain and domain.replace("-", "") != sender_domain.replace("-", ""):
            score += 1
            reasons.append("Possible lookalike domain")
        
        item["analysis"] = {
            "score": score,
            "reasons": reasons,
            "is_malicious": score >= URL_MALICIOUS_THRESHOLD
        }

    return case

