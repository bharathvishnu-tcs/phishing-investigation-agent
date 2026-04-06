def classify(case):
    
    url_analysis = case.get("url_analysis", [])
    malicious_url = any(u.get("is_malicious") for u in url_analysis)

    attachments = case.get("attachment_analysis", [])
    malicious_attachment = any(a.get("is_malicious") for a in attachments)

    spoofed = case.get("spoofing", {}).get("is_spoofed", False)
    link_clicked = case.get("user_interaction", {}).get("link_clicked", False)
    attachment_opened = case.get("user_interaction", {}).get("attachment_opened", False)

    creds = case.get("identity", {}).get("credentials_submitted", False)
    multiple_failed_logins = case.get("identity", {}).get("multiple_failed_logins", False)

    domain_age_days = case.get("enrichment", {}).get("urls", [{}])[0].get("domain_age_days", 999)

    classification = "False Positive"
    severity = "low"
    reasons = []
    features = {
        "has_malicious_url": malicious_url,
        "has_malicious_attachment": malicious_attachment,
        "is_spoofed": spoofed,
        "link_clicked": link_clicked,
        "attachment_opened": attachment_opened,
        "creds": creds,
        "multiple_failed_logins": multiple_failed_logins,
        "new_domain": domain_age_days < 7,   
    }

    SCENARIOS = [

    # ===== IMPACT (Critical) =====
    {
        "name": "Credential Harvesting (Account Compromise)",
        "severity": "critical",
        "when": lambda f: f["creds"]
    },
    {
        "name": "Account Takeover Attempt After Phishing",
        "severity": "critical",
        "when": lambda f: f["multiple_failed_logins"] and (f["has_malicious_url"] or f["is_spoofed"])
    },

    # ===== DELIVERY + PAYLOAD (High) =====
    {
        "name": "Malware Execution via Phishing Attachment",
        "severity": "high",
        "when": lambda f: f["attachment_opened"] and f["has_malicious_attachment"]
    },
    {
        "name": "User Clicked Malicious Phishing Link",
        "severity": "high",
        "when": lambda f: f["link_clicked"] and f["has_malicious_url"]
    },

    # ===== DELIVERY ONLY (Medium-High) =====
    {
        "name": "Malware Delivery Attempt (Attachment Not Opened)",
        "severity": "medium",
        "when": lambda f: f["has_malicious_attachment"]
    },
    {
        "name": "Phishing Link Clicked (No Known Malicious Verdict Yet)",
        "severity": "medium",
        "when": lambda f: f["link_clicked"]
    },

    # ===== INTENT ONLY (Medium) =====
    {
        "name": "Spoofed Sender Phishing Attempt",
        "severity": "medium",
        "when": lambda f: f["is_spoofed"]
    },
    {
        "name": "New Domain Phishing Lure",
        "severity": "medium",
        "when": lambda f: f["new_domain"]
    },
    {
        "name": "Malicious URL Detected (No Interaction)",
        "severity": "medium",
        "when": lambda f: f["has_malicious_url"]
    },

    # ===== LOW CONFIDENCE =====
    {
        "name": "Suspicious Email Indicators",
        "severity": "low",
        "when": lambda f: True
    }
    ]
    matched = None

    for scenario in SCENARIOS:
        if scenario["when"](features):
            matched = scenario
            break

    if matched:
        classification = matched["name"]
        severity = matched["severity"]
    else:
        classification = "False Positive"
        severity = "low"

    reasons = [k for k, v in features.items() if v]
    
    case["decision"] = {
        "classification": classification,
        "severity": severity,
        "reasons": reasons
    }
    return case