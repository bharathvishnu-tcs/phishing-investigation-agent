def ioc_sweep(case: dict) -> dict:
    """
    Performs an IOC sweep on the current case.
    Checks collected domains, URLs, file hashes, and IPs against known suspicious indicators.
    """

    iocs = case.get("iocs", {})
    sweep_results = {
        "matches_found": False,
        "affected_users": [],
        "matched_iocs": [],
        "notes": []
    }

    # Get the affected user(s) from the case
    recipients = case.get("email_evidence", {}).get("recipient_emails", [])

    # Example simulated IOC database
    suspicious_domains = ["login-microsoftonline-security.com", "secure-paypal.net"]
    suspicious_urls = ["http://login-microsoftonline-security.com/auth"]
    suspicious_hashes = ["abc123", "def456"]
    suspicious_ips = ["45.77.120.33", "185.225.69.45"]

    # Check domains
    for domain in iocs.get("domains", []):
        if domain in suspicious_domains:
            sweep_results["matches_found"] = True
            sweep_results["affected_users"].extend(recipients)
            sweep_results["matched_iocs"].append(domain)
            sweep_results["notes"].append(f"Suspicious domain detected: {domain}")

    # Check URLs
    for url in iocs.get("urls", []):
        if url in suspicious_urls:
            sweep_results["matches_found"] = True
            sweep_results["affected_users"].extend(recipients)
            sweep_results["matched_iocs"].append(url)
            sweep_results["notes"].append(f"Suspicious URL detected: {url}")

    # Check file hashes
    for file_hash in iocs.get("file_hashes", []):
        if file_hash in suspicious_hashes:
            sweep_results["matches_found"] = True
            sweep_results["affected_users"].extend(recipients)
            sweep_results["matched_iocs"].append(file_hash)
            sweep_results["notes"].append(f"Malicious file hash detected: {file_hash}")

    # Check IPs
    for ip in iocs.get("ip_addresses", []):
        if ip in suspicious_ips:
            sweep_results["matches_found"] = True
            sweep_results["affected_users"].extend(recipients)
            sweep_results["matched_iocs"].append(ip)
            sweep_results["notes"].append(f"Suspicious IP detected: {ip}")

    # Deduplicate affected users and matched IOCs
    sweep_results["affected_users"] = list(set(sweep_results["affected_users"]))
    sweep_results["matched_iocs"] = list(set(sweep_results["matched_iocs"]))

    case["ioc_sweep"] = sweep_results
    return case