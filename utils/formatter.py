def format_output(case):
    return{
        "case_id" : case.get("case_id"),
        "classification": case.get("decision",{}).get("classification"),
        "endpoint_evidence":case.get("endpoint_evidence"),
        "severity": case.get("decision",{}).get("severity"),
        "risk_score": case.get("risk",{}).get("score"),
        "risk_level": case.get("risk",{}).get("level"),
        "actions": case.get("response"),
        "summary_llm": case.get("summary"),
        "reasoning_llm": case.get("llm_reasoning")    
    }