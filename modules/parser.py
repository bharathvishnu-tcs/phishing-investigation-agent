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

    alert["source_system"] = raw.get("source","M365")
    alert["detection_type"] = "SystemDetected"
    alert["alert_type"] = raw.get("ThreatTypes")
    alert["severity"] = "Medium"

    event_time = raw.get("TimeGenerated")
    try:
        alert["event_timestamp"] = datetime.fromisoformat(event_time).isoformat()
    except:
        alert["event_timestamp"] = "N/A"

    alert["ingestion_timestamp"] = datetime.utcnow().isoformat()

    sender = raw.get("SenderFromAddress", "").lower()
    recipient = raw.get("RecipientEmailAddress", "").lower()

    #email metadata
    alert["sender_email"] = sender
    alert["sender_domain"] = raw.get("SenderDomain", "").lower() or extract_domain(sender)
    alert["recipient_emails"] = [recipient] if recipient else []
    alert["subject"] = raw.get("Subject", "")
    alert["message_id"] = raw.get("NetworkMessageId")
    alert["delivery_action"] = raw.get("DeliveryAction")
    alert["urls"] = []

    # Attachments (email level evidence only)
    attachment_count = raw.get("AttachmentCount", 0)

    if attachment_count > 0:
        alert["attachments"] = ["unknown_attachment"]
    else:
        alert["attachments"] = []

    alert["attachments_hash"] = []

    # Authentication / spoofing indicators
    alert["authentication_results"] = raw.get("AuthenticationDetails", {})
    alert["detection_reason"] = raw.get(
        "DetectionMethods",
        "Suspicious email indicators detected"
    )
    alert["vendor_confidence"] = raw.get("ConfidenceLevel", "Unknown")

    alert["raw_log"] = raw

    return alert


def load_and_normalize(path):
    with open(path,"r") as f:
        data = json.load(f)
    
    normalized = []
    for raw in data:
        normalized.append(normalize(raw))
    
    return normalized
