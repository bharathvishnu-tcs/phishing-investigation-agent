def analyze_identity(case):
    
    interaction = case.get("user_interaction", {})
    
    #Needs to be changed to AzureAD logs
    identity = {
        "credentials_submitted": False,
        "impossible_travel": False,
        "multiple_failed_logins": False,
        "mfa_fatigue": False
    }
    
    if interaction.get("link_clicked"):
        identity["credentials_submitted"] = True
    
    case["identity"] = identity
    
    return case