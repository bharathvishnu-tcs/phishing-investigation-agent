import uuid
from datetime import datetime

def initialize_case(alert):
    case = {
        "case_id": str(uuid.uuid4()),
        "source": alert.get("source_system"),
        "timestamp": datetime.utcnow().isoformat(),
        "email" : {
            "sender_email": alert.get("sender_email"),
            "subject" : alert.get("subject"),
            "urls": alert.get("urls",[])
        },
        "enrichment": {},
        "url_analysis": [],
        "attachment_analysis": [],
        "spoofing": {},
        "user_interaction": {},
        "endpoint": {},
        "identity": {},
        "iocs": {},
        "decision": {},
        "response": [],
        "summary": "",
        "llm_reasoning": "",
        "summary2": ""
    }
    return case