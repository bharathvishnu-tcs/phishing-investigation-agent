import difflib

def analyze_spoofing(case):
    sender_email = case.get("email", {}).get("sender_email", "")
    sender_domain = case.get("enrichment", {}).get("sender_domain", "")

    spoof_score = 0
    reasons = []

    legit_domains = ["paypal.com", "microsoft.com", "google.com"]

    if sender_domain:
        for legit in legit_domains:
            similarity = difflib.SequenceMatcher(
                None, sender_domain.lower(), legit.lower()
            ).ratio()

            # Typosquat detection
            if similarity > 0.8 and sender_domain.lower() != legit.lower():
                spoof_score += 3
                reasons.append(f"Typosquatting detected (similar to {legit})")

    # Generic role-based sender detection
    generic_keywords = ["support", "security", "admin", "billing", "hr"]

    if any(keyword in sender_email.lower() for keyword in generic_keywords):
        spoof_score += 1
        reasons.append("Generic role-based sender name used")

    # Combine with header auth failure
    header_auth = case.get("header_analysis", {})
    if header_auth.get("dmarc") == "fail":
        spoof_score += 2
        reasons.append("DMARC failure increases spoof likelihood")

    case["spoofing"] = {
        "spoof_score": spoof_score,
        "is_spoofed": spoof_score >= 3,
        "reasons": reasons
    }

    return case