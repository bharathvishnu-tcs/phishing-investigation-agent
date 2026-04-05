from typing import TypedDict
class CaseState(TypedDict):
    case_id: str
    source: str
    timestamp: str

    enrichment: dict
    email: dict

    header_analysis: dict
    url_analysis: list
    attachment_analysis: list

    spoofing: dict
    user_interaction: dict

    endpoint: dict
    identity: dict

    iocs: dict

    raw_log: dict

    decision: dict
    response: list
    risk: dict

    summary: str
    llm_reasoning: str
    summary2: str

    authentication_results: str