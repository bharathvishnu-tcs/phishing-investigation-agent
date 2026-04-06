from utils.helper import extract_domain,find_suspicious_keywords,simulate_domain_age

def enrich(case):
    email_data = case.get("email", {})
    urls = email_data.get("urls", [])
    
    enriched_urls = []
    
    for url in urls:
        domain = extract_domain(url)
        
        enriched_urls.append({
            "url": url,
            "domain": domain,
            "keywords": find_suspicious_keywords(url)
        })
    
    case["enrichment"]["urls"] = enriched_urls

    for item in enriched_urls:
        domain = item["domain"]
        age = simulate_domain_age(domain)

        item["domain_age_days"] = age
        item["is_new_domain"] = age < 7
    
    # Enrich sender domain
    sender_email = email_data.get("sender_email", "")
    
    if "@" in sender_email:
        sender_domain = sender_email.split("@")[1]
    else:
        sender_domain = None
    
    case["enrichment"]["sender_domain"] = sender_domain

    auth = case.get("authentication_results", "").lower()
    case["raw_log"]["spf_result"] = "fail" if "spf=fail" in auth else "pass"
    case["raw_log"]["dkim_result"] = "fail" if "dkim=fail" in auth else "pass"
    case["raw_log"]["dmarc_result"] = "fail" if "dmarc=fail" in auth else "pass"
    
    return case