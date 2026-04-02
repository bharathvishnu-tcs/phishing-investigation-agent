def respond(case):
    
    decision = case.get("decision", {})
    classification = decision.get("classification", "")
    
    actions = []
    
    actions.append("Delete email from all mailboxes")
    actions.append("Block sender domain")
    
    if classification == "Attempted Phishing":
        actions.append("Block malicious URLs")
    
    elif classification == "Phishing Incident":
        actions.append("Block URLs")
        actions.append("Monitor user activity")
    
    elif classification == "Account Compromise":
        actions.append("Force password reset")
        actions.append("Revoke active sessions")
        actions.append("Enable MFA")
        actions.append("Monitor identity logs")
    
    case["response"] = actions
    
    return case