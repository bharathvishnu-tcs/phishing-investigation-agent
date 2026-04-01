from urllib.parse import urlparse
from datetime import datetime
import difflib
 
 
def enrich(normalized_alert: dict) -> dict:
    """
    Main enrichment entry point.
    Takes normalized alert and returns enriched data.
    """
 
    case = {}
    case["case_id"] = normalized_alert.get("case_id")
    case["source"] = normalized_alert.get("source_system")
    case["timestamp"] = datetime.utcnow().isoformat()
 
    # ------------------
    # ENRICHMENT BLOCKS
    # ------------------
    case["email"] = _enrich_email(normalized_alert)
    case["iocs"] = _extract_iocs(normalized_alert)
    case["spoofing"] = _enrich_spoofing(normalized_alert)
    case["enrichment"] = _enrich_metadata(normalized_alert)
 
    # Empty placeholders for next stages
    case["user_interaction"] = {}
    case["endpoint"] = {}
    case["identity"] = {}
    case["decision"] = {}
    case["response"] = []
    case["summary"] = None
 
    return case
 
 
def _enrich_email(alert: dict) -> dict:
    sender_email = alert.get("sender_email")
    sender_domain = None
 
    if sender_email and "@" in sender_email:
        sender_domain = sender_email.split("@")[1].lower()
 
    return {
        "sender_email": sender_email,
        "sender_domain": sender_domain,
        "recipient_emails": alert.get("recipient_emails", []),
        "subject": alert.get("subject"),
        "urls": alert.get("urls", []),
        "attachments": alert.get("attachments", []),
        "attachment_hashes": alert.get("attachment_hashes", [])
    }
 
 
def _extract_iocs(alert: dict) -> dict:
    iocs = {
        "urls": [],
        "domains": [],
        "hashes": [],
        "ips": [],
        "email_addresses": []
    }
 
    # URLs & Domains
    for url in alert.get("urls", []):
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
 
        iocs["urls"].append({
            "type": "url",
            "value": url,
            "source": "email"
        })
 
        iocs["domains"].append({
            "type": "domain",
            "value": domain,
            "source": "url"
        })
 
    # Attachment hashes
    for h in alert.get("attachment_hashes", []):
        iocs["hashes"].append({
            "type": "hash",
            "value": h,
            "source": "attachment"
        })
 
    # Email addresses
    if alert.get("sender_email"):
        iocs["email_addresses"].append({
            "type": "email",
            "value": alert["sender_email"],
            "source": "email_header"
        })
 
    return iocs
 
 
def _enrich_spoofing(alert: dict) -> dict:
    """
    Lightweight spoofing enrichment.
    No verdict, only indicators.
    """
 
    sender_domain = alert.get("sender_domain")
    suspicious_domain = None
 
    # Example look-alike check
    known_brands = ["paypal.com", "nike.com", "amazon.com"]
    for legit_domain in known_brands:
        if sender_domain and _is_lookalike(sender_domain, legit_domain):
            suspicious_domain = legit_domain
 
    return {
        "possible_spoofing": suspicious_domain is not None,
        "observed_domain": sender_domain,
        "impersonated_domain": suspicious_domain,
        "auth_failures_present": "SPF" in (alert.get("detection_logic") or "")
    }
 
 
def _enrich_metadata(alert: dict) -> dict:
    return {
        "alert_type": alert.get("alert_type"),
        "severity": alert.get("severity"),
        "detection_type": alert.get("detection_type"),
        "detection_logic": alert.get("detection_logic"),
        "vendor_confidence": alert.get("vendor_confidence"),
        "first_seen": alert.get("event_timestamp"),
        "last_updated": datetime.utcnow().isoformat()
    }
 
 
def _is_lookalike(domain1: str, domain2: str) -> bool:
    return difflib.SequenceMatcher(None, domain1, domain2).ratio() > 0.85