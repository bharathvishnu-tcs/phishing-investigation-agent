def classify(reasons, enrichment):
    if not reasons:
        return "False Positive"
    if enrichment["url_rep"] == "Malicious":
        return "Phishing"
    return "Suspicious"

