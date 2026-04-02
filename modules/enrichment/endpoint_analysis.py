def analyze_endpoint(case):
    
    interaction = case.get("user_interaction", {})
    
    #Needs to be changed to EDRlogs
    endpoint = {
        "suspicious_process": False,
        "powershell_activity": False,
        "registry_persistence": False,
        "c2_traffic": False
    }
    
    if interaction.get("attachment_opened"):
        endpoint["suspicious_process"] = True
        endpoint["powershell_activity"] = True
    
    case["endpoint"] = endpoint
    
    return case