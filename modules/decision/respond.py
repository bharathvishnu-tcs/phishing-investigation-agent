def respond(case):

    decision = case.get("decision", {})
    risk = case.get("risk", {})

    attack_chain = decision.get("attack_chain", [])
    attack_stage = decision.get("attack_stage", "")
    risk_level = risk.get("level", "Low")

    actions = []

  
    if "Data Exfiltration" in attack_chain:
        actions = [
            "Isolate affected user account",
            "Block attacker IP and domains",
            "Revoke all active sessions",
            "Force password reset",
            "Remove malicious mailbox rules",
            "Audit accessed/downloaded data",
            "Notify security team and management"
        ]

    elif "Persistence" in attack_chain:
        actions = [
            "Remove malicious mailbox rules",
            "Revoke active sessions",
            "Force password reset",
            "Block attacker infrastructure",
            "Monitor account for further suspicious activity"
        ]

    elif "Credential Theft" in attack_chain:
        actions = [
            "Force password reset",
            "Revoke active sessions",
            "Enable/Enforce MFA",
            "Monitor login activity",
            "Check for suspicious access patterns"
        ]



    elif "User Interaction" in attack_chain:
        actions = [
            "Delete email from all mailboxes",
            "Block sender domain",
            "Block malicious URLs",
            "Monitor user activity",
            "Warn user about phishing attempt"
        ]



    elif attack_stage == "Initial Access":
        actions = [
            "Delete email from all mailboxes",
            "Block sender domain",
            "Add domain to watchlist",
            "Review email security filters"
        ]



    else:
        actions = [
            "Delete email from all mailboxes",
            "Block sender domain"
        ]



    if risk_level == "Critical":
        actions.append("Escalate incident to Tier 2/3 SOC")
        actions.append("Trigger automated SOAR playbook")

    elif risk_level == "High":
        actions.append("Escalate for analyst review")


    case["response"] = actions

    return case