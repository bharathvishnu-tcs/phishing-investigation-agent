from typing import List, TypedDict, Optional

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
    attachment_hashes: Optional[List[str]]

    device_id: Optional[str]
    hostname: Optional[str]
    user_principal: Optional[str]

    detection_reason: Optional[str]
    authentication_results: Optional[dict]
    # detection_logic: Optional[str]
    vendor_confidence: Optional[str]

    url_evidence: Optional[List[dict]]
    attachment_evidence: Optional[List[dict]]

    sign_in_evidence: Optional[List[dict]]
    impossible_travel: Optional[dict]

    endpoint_evidence: Optional[List[dict]]

    mailbox_rule_evidence: Optional[List[dict]]

    data_access_evidence: Optional[List[dict]]

    timeline: Optional[List[dict]]

    user_compromised: Optional[bool]
    post_click_activity: Optional[bool]
    data_exfiltration: Optional[bool]
    persistence_established: Optional[bool]
    attacker_ip: Optional[str]
    attacker_location: Optional[str]
    malware_execution: Optional[bool]

    raw_log: dict