def analyze_header(case):
    """
    Uses normalized authentication results from email_evidence
    and converts them into risk scoring + reasoning.
    """

    email_evidence = case.get("email_evidence", {})
    auth = email_evidence.get("authentication_results", {})

    spf = auth.get("spf", "unknown").lower()
    dkim = auth.get("dkim", "unknown").lower()
    dmarc = auth.get("dmarc", "unknown").lower()

    reasons = []
    risk_score = 0

    if spf == "fail":
        reasons.append("SPF authentication failed")
        risk_score += 10

    if dkim == "fail":
        reasons.append("DKIM authentication failed")
        risk_score += 10

    if dmarc == "fail":
        reasons.append("DMARC authentication failed")
        risk_score += 15

    # Very important SOC logic
    if spf == "pass" and dkim == "pass" and dmarc == "pass":
        reasons.append("All authentication checks passed")

    case["header_analysis"] = {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "score": risk_score,
        "is_suspicious": risk_score > 0,
        "reasons": reasons
    }

    return case