from utils.helper import extract_domain,find_suspicious_keywords

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
    
    # Enrich sender domain
    sender_email = email_data.get("sender_email", "")
    
    if "@" in sender_email:
        sender_domain = sender_email.split("@")[1]
    else:
        sender_domain = None
    
    case["enrichment"]["sender_domain"] = sender_domain
    
    return case