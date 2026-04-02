from typing import TypedDict
class CaseState(TypedDict):
    case_id: str
    source: str
    timestamp: str

    enrichment: dict
    email: dict

    url_analysis: list
    attachment_analysis: list

    spoofing: dict
    user_interaction: dict

    endpoint: dict
    identity: dict

    iocs: dict

    decision: dict
    response: list

    summary: str