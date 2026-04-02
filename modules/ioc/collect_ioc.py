def collect_ioc(case):
    
    iocs = {
        "domains": set(),
        "urls": set(),
        "sender_emails": set(),
        "ip_addresses": set(),
        "file_hashes": set()
    }
    
    sender = case.get("email", {}).get("sender_email")
    if sender:
        iocs["sender_emails"].add(sender)
    
   
    enriched_urls = case.get("enrichment", {}).get("urls", [])
    
    for item in enriched_urls:
        iocs["urls"].add(item["url"])
        iocs["domains"].add(item["domain"])
    
    # From original alert (if extended later)
    # hashes, IPs etc. can also be added
    hashes = case.get("email", {}).get("attachment_hashes", [])
    for h in hashes:
        iocs["file_hashes"].add(h)

    case["iocs"] = {k: list(v) for k, v in iocs.items()}
    
    return case