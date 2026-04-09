from llm.classifier import llm_classify


def classify(case):

    # =========================
    # EXTRACT DATA
    # =========================
    email = case.get("email_evidence", {})
    url_clicks = case.get("url_click_evidence", [])
    attachments = case.get("attachment_evidence", [])
    endpoint = case.get("endpoint_evidence", {})
    signins = case.get("sign_in_evidence", {})

    spoofed = case.get("spoofing_evidence", {}).get("is_spoofed", False)
    header_suspicious = case.get("header_analysis", {}).get("is_suspicious", False)

    malicious_url = any(u.get("analysis", {}).get("is_malicious") for u in url_clicks)
    link_clicked = any(u.get("clicked_through") for u in url_clicks)

    malicious_attachment = any(a.get("is_malicious") for a in attachments)
    attachment_opened = any(a.get("opened") for a in attachments)

    creds = signins.get("credentials_submitted", False)
    impossible_travel = case.get("impossible_travel", False)

    endpoint_suspicious = endpoint.get("verdict") in ["Medium Risk", "High Risk"]

    persistence = len(case.get("mailbox_rule_evidence", [])) > 0
    data_exfiltration = len(case.get("data_access_evidence", [])) > 0

    email_delivered = case.get("user_interaction", {}).get("email_delivered", False)

    
    stages = {
        "delivery": email_delivered,
        "interaction": link_clicked or attachment_opened,
        "execution": endpoint_suspicious,
        "credential_access": creds,
        "lateral_movement": impossible_travel,
        "persistence": persistence,
        "exfiltration": data_exfiltration
    }

    attack_chain = []

    if stages["delivery"]:
        attack_chain.append("Initial Access")

    if stages["interaction"]:
        attack_chain.append("User Interaction")

    if stages["execution"]:
        attack_chain.append("Execution")

    if stages["credential_access"]:
        attack_chain.append("Credential Theft")

    if stages["lateral_movement"]:
        attack_chain.append("Account Takeover")

    if stages["persistence"]:
        attack_chain.append("Persistence")

    if stages["exfiltration"]:
        attack_chain.append("Data Exfiltration")

    
    if stages["credential_access"] or stages["persistence"] or stages["exfiltration"]:
        classification = "Phishing"
        attack_stage = "Post-Compromise"

    elif stages["interaction"]:
        classification = "Attempted Phishing"
        attack_stage = "User Interaction"

    elif spoofed or header_suspicious:
        classification = "Suspicious"
        attack_stage = "Initial Access"

    else:
        classification = "Legitimate"
        attack_stage = "Initial Access"


    context = {
        "email": email,
        "url_activity": url_clicks,
        "identity": signins,
        "endpoint": endpoint,
        "ioc_sweep": case.get("ioc_sweep", {}),
        "flags": stages
    }

    llm_result = llm_classify(context)

    confidence = 0.6  # fallback default
    reasoning = ["Rule-based classification used"]


    if llm_result and llm_result.get("confidence", 0) >= 0.7:

        classification = llm_result.get("classification", classification)
        attack_stage = llm_result.get("attack_stage", attack_stage)
        confidence = llm_result.get("confidence", confidence)
        reasoning = llm_result.get("reasoning", [])

        llm_chain = llm_result.get("attack_chain", [])
        attack_chain = list(set(attack_chain + llm_chain))


    case["decision"] = {
        "classification": classification,
        "attack_stage": attack_stage,
        "attack_chain": attack_chain,
        "attack_stages": stages,
        "confidence": round(confidence, 2),
        "reasons": [k for k, v in stages.items() if v],
        "llm_reasoning": reasoning
    }

    return case