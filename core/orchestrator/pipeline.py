import uuid
from datetime import datetime


def initialize_case(alert: dict) -> dict:
    case = {
        
        # Core identifiers  
        "case_id": str(uuid.uuid4()),
        "source": alert.get("source_system"),
        "timestamp": datetime.utcnow().isoformat(),

        
        # Evidence buckets
        "email_evidence": {
            "sender_email": alert.get("sender_email"),
            "sender_domain": alert.get("sender_domain"),
            "recipient_emails": alert.get("recipient_emails", []),
            "subject": alert.get("subject"),
            "urls": alert.get("urls", []),
            "authentication_results": alert.get("authentication_results", {}),
            "detection_reason": alert.get("detection_reason"),
            "message_id": alert.get("message_id"),
        },

        "url_click_evidence": [],
        "attachment_evidence": [],
        "endpoint_evidence": [],
        "sign_in_evidence": [],
        "impossible_travel": {},
        "mailbox_rule_evidence": [],
        "data_access_evidence": [],

        
        # Timeline (every node appends here) 
        "timeline": [],

        
        # Investigation flags
        
        "user_compromised": False,
        "persistence_established": False,
        "data_exfiltration": False,
        "malware_execution": False,
        "attacker_ip": "",
        "attacker_location": "",

        
        # IOCs
        
        "iocs": {},

        
        # Decisioning & response
        
        "decision": {},
        "response": [],
        "risk": {},

        
        # LLM outputs
        
        "summary": "",
        "llm_reasoning": "",

        # Backup raw log
        "raw_log": alert.get("raw_log", {}),
    }

    return case