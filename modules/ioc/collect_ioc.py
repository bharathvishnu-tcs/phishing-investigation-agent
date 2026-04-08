from utils.helper import extract_domain
def collect_ioc(case: dict) -> dict:
    """
    Collects Indicators of Compromise (IOCs) from the normalized case state.
    Pulls from email evidence, URL analysis, attachments, sign-ins, and endpoint telemetry.
    """

    iocs = {
        "domains": set(),
        "urls": set(),
        "sender_emails": set(),
        "ip_addresses": set(),
        "file_hashes": set()
    }

    # Email evidence
    email = case.get("email_evidence", {})
    sender = email.get("sender_email")
    if sender:
        iocs["sender_emails"].add(sender)
    # Domains
    sender_domain = email.get("sender_domain")
    if sender_domain:
        iocs["domains"].add(sender_domain)

    # URL evidence
    for item in case.get("url_click_evidence", []):
        url = item.get("url")
        domain = extract_domain(url)
        if url:
            iocs["urls"].add(url)
        if domain:
            iocs["domains"].add(domain)

    # Attachment evidence
    for attachment in case.get("attachment_evidence", []):
        file_hash = attachment.get("hash")
        if file_hash:
            iocs["file_hashes"].add(file_hash)

    # Sign-in / endpoint evidence for IPs
    for url in case.get("url_click_evidence", []):
        ip = url.get("ip_address")
        if ip:
            iocs["ip_addresses"].add(ip)

    endpoint = case.get("endpoint_evidence", {}).get("normalized", {})
    ip = endpoint.get("ip")
    if ip:
        iocs["ip_addresses"].add(ip)

    # Impossible travel detection IPs
    # impossible = case.get("impossible_travel", {})
    # for key in ["Login1", "Login2"]:
    #     login = impossible.get(key, {})
    #     ip = login.get("IP")
    #     if ip:
    #         iocs["ip_addresses"].add(ip)

    # Convert sets to lists for JSON serialization
    case["iocs"] = {k: list(v) for k, v in iocs.items()}
    print("Collected IOCs:", case["iocs"])
    return case