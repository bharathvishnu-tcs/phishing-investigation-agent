import uuid
from datetime import datetime

def initialize_case(alert):
    print(type(alert.get("raw_log")))
    case = {
        "case_id": str(uuid.uuid4()),
        "source": alert.get("source_system"),
        "timestamp": datetime.utcnow().isoformat(),
        "email" : {
            "sender_email": alert.get("sender_email"),
            "subject" : alert.get("subject"),
            "urls": alert.get("urls",[]),
            "attachments": alert.get("attachment",[]),
            "attachments_hashes": alert.get("attachment.hashes",[])
        },
        "enrichment": {},
        "url_analysis": [],
        "attachment_analysis": [],
        "spoofing": {},
        "user_interaction": {},
        "endpoint": {},
        "identity": {},
        "iocs": {},

        "raw_log":alert.get("raw_log",{}),

        "decision": {},
        "response": [],
        "risk":{},
        "summary": "",
        "llm_reasoning": "",
        "summary2": ""
    }
    return case