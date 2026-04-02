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
    
    return case