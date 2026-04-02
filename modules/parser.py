import json
from datetime import datetime
from core.models.alert import NormalizedAlert

def generate_alert_id(raw):
    return f"{hash(str(raw)) % 100000}"

def extract_domain(email):
    if email and "@" in email:
        return email.split("@")[-1].lower()
    return None

def normalize(raw:dict) -> NormalizedAlert:
    alert: NormalizedAlert = {}

    alert["alert_id"] = generate_alert_id(raw)
    alert["case_id"] = None

    alert["source_system"] = raw.get("alert_source","M365")
    alert["detection_type"] = "SystemDetected"
    alert["alert_type"] = "Phishing"
    alert["severity"] = "Medium"

    event_tume = raw.get("timestamp")
    try:
        alert["event_timestamp"] = datetime.fromisoformat(event_time).isoformat()
    except:
        alert["event_timestamp"] = "N/A"

    alert["ingestion_timestamp"] = datetime.utcnow().isoformat()

    alert["sender_email"] = raw.get("sender","").lower()
    alert["sender_domain"] = extract_domain(alert["sender_email"])
    alert["recipient_emails"] = [raw.get("recipient","").lower()]
    alert["subject"] = raw.get("subject")

    alert["urls"] = raw.get("urls",[])

    attachment = raw.get("attachment",{})
    if attachment.get("exists"):
        alert["attachment"] = [attachment.get("name")]
        alert["attachment_hashes"] = [attachment.get("hash")]
    else:
        alert["attachments"] = []
        alert["attachment_hases"] = []

    alert["detection_reason"] = "Suspicious email indicators detected"
    # alert["vendor_confidence"] = 70

    alert["raw_log"] = raw

    return alert


def load_and_normalize(path):
    with open(path,"r") as f:
        data = json.load(f)
    
    normalized = []
    for raw in data:
        normalized.append(normalize(raw))
    
    return normalized
