def classify(case):


    email = case.get("email_evidence", {})
    url_clicks = case.get("url_click_evidence", [])
    attachments = case.get("attachment_evidence", [])
    endpoint = case.get("endpoint_evidence", {})
    signins = case.get("sign_in_evidence", {})
    
    spoofed = case.get("spoofing", {}).get("is_spoofed", False)
    header_suspicious = case.get("header_analysis", {}).get("is_suspicious", False)

    malicious_url = any(u.get("analysis", {}).get("is_malicious") for u in url_clicks)
    link_clicked = any(u.get("clicked_through") for u in url_clicks)

    malicious_attachment = any(a.get("analysis", {}).get("is_malicious") for a in attachments)
    attachment_opened = any(a.get("opened") for a in attachments)

    creds = signins.get("credentials_submitted", False)
    impossible_travel = case.get("impossible_travel", False)

    endpoint_suspicious = endpoint.get("verdict") in ["Medium Risk", "High Risk"]

    persistence = len(case.get("mailbox_rule_evidence", [])) > 0
    data_exfiltration = len(case.get("data_access_evidence", [])) > 0

    email_delivered = case.get("user_interaction", {}).get("email_delivered", False)


    # =========================
    stages = {
        "delivery": email_delivered,
        "interaction": link_clicked or attachment_opened,
        "execution": endpoint_suspicious,
        "credential_access": creds,
        "persistence": persistence,
        "lateral_movement": impossible_travel,
        "exfiltration": data_exfiltration
    }

 
    if stages["credential_access"] and stages["interaction"]:
        classification = "Confirmed Phishing → Credential Compromise"
        severity = "critical"

    elif stages["exfiltration"]:
        classification = "Data Exfiltration Detected"
        severity = "critical"

    elif stages["persistence"]:
        classification = "Post-Compromise Persistence Established"
        severity = "critical"

    elif stages["lateral_movement"]:
        classification = "Account Takeover / Suspicious Login Activity"
        severity = "high"

    # ===== HIGH =====
    elif stages["interaction"] and malicious_url:
        classification = "User Clicked Verified Malicious Phishing Link"
        severity = "high"

    elif stages["execution"] and malicious_attachment:
        classification = "Malware Execution via Attachment"
        severity = "high"

    # ===== MEDIUM =====
    elif malicious_url:
        classification = "Malicious Phishing Link Delivered"
        severity = "medium"

    elif malicious_attachment:
        classification = "Malicious Attachment Delivered"
        severity = "medium"

    elif spoofed or header_suspicious:
        classification = "Spoofed / Suspicious Email"
        severity = "medium"

    # ===== LOW =====
    else:
        classification = "Suspicious / Low Confidence Phishing"
        severity = "low"

    reasons = [k for k, v in stages.items() if v]

    case["decision"] = {
        "classification": classification,
        "severity": severity,
        "attack_stages": stages,
        "reasons": reasons
    }

    return case