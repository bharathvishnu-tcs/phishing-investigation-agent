import uuid
from datetime import datetime
def initialize_case(alert):
    case = {
        "case_id": str(uuid.uuid4()),
        "source": alert.get("source_system")
        "timestamp": datetime.get("source")
    }
    return case