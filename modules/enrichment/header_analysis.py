from unittest import case


def analyze_header(case):
    raw_log = case.get("raw_log", {})
    headers = case.get("headers", {})
    header_text = str(headers).lower()

    # Extract auth results from raw_log OR headers
    spf = raw_log.get("spf_result", "unknown")
    dkim = raw_log.get("dkim_result", "unknown")
    dmarc = raw_log.get("dmarc_result", "unknown")

    # Fallback: parse from authentication-results header if present
    auth_header = header_text

    if "spf=fail" in auth_header:
        spf = "fail"
    elif "spf=pass" in auth_header:
        spf = "pass"

    if "dkim=fail" in auth_header:
        dkim = "fail"
    elif "dkim=pass" in auth_header:
        dkim = "pass"

    if "dmarc=fail" in auth_header:
        dmarc = "fail"
    elif "dmarc=pass" in auth_header:
        dmarc = "pass"

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

    is_suspicious = risk_score > 0

    case["header_analysis"] = {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "auth_risk": risk_score,
        "is_suspicious": is_suspicious,
        "reasons": reasons
    }

    return case