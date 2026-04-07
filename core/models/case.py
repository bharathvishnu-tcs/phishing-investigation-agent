from typing import TypedDict, List, Dict, Optional
class CaseState(TypedDict, total=False):

    # Core_identifiers
    case_id: str
    source: str
    timestamp: str

    # Original email evidence
    email_evidence: Dict

    # User URL interaction evidence
    url_click_evidence: List[Dict]

    # User attachment interaction evidence
    attachment_evidence: List[Dict]

    # Endpoint/browser/process evidence
    endpoint_evidence: List[Dict]

    # Identity & sign-in evidence
    sign_in_evidence: List[Dict]
    impossible_travel: bool

    # Mailbox persistence evidence (rules/forwarding)
    mailbox_rule_evidence: List[Dict]

    # Data access / potential exfiltration evidence
    data_access_evidence: List[Dict]

    # Correlated timeline (critical for LLM reasoning)
    timeline: List[Dict]

    #Checking url
    urls: List[Dict]

    # Investigation flags (derived progressively by nodes)
    user_compromised: bool
    post_click_activity: bool
    persistence_established: bool
    data_exfiltration: bool
    attacker_ip: str
    attacker_location: str
    malware_execution: bool
    
    # IOCs extracted during investigation
    iocs: dict

    # Decisioning & response
    decision: dict
    response: list
    risk: dict

    # LLM outputs
    summary: str
    llm_reasoning: str

    # Raw log backup (optional reference)
    raw_log: Dict



   