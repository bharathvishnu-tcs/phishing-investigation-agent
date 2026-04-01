from typing import List, TypedDict

class NormalizedAlert(TypedDict, total=False):
    alert_id: str
    case_id : Optional[str]

    source_system : str
    detection_type : str
    alert_type: str
    severity : str

    event_timestamp: str
    ingestion_timestamp : str

    message_id: Optional[str]

    sender_email: Optional[str]
    sender_ip: Optional[str]
    sender_domain: Optional[str]

    recipient_emails: Optional[List[str]]
    subject: Optional[str]

    urls: Optional[List[str]]
    attachments: Optional[List[str]]
    attachments_hash: Optional[List[str]]

    device_id: Optional[str]
    hostname: Optional[str]
    user_principal: Optional[str]

    detection_reason: Optional[str]
    detection_logic: Optional[str]
    vendor_confidence: Optional[int]

    raw_log: str