def respond(case):
    decision = case.get("decision", {})
    classification = decision.get("classification", "")

    RESPONSE_PLAYBOOK = {

        # ===== CRITICAL =====
        "Credential Harvesting (Account Compromise)": [
            "Delete email from all mailboxes",
            "Block sender domain",
            "Block malicious URLs",
            "Force password reset for user",
            "Revoke active sessions",
            "Enable/Enforce MFA",
            "Check for lateral movement",
            "Monitor identity and login logs"
        ],

        "Account Takeover Attempt After Phishing": [
            "Delete email from all mailboxes",
            "Block sender domain",
            "Force password reset for user",
            "Monitor failed login sources",
            "Enable/Enforce MFA",
            "Investigate login IP addresses"
        ],

        # ===== HIGH =====
        "Malware Execution via Phishing Attachment": [
            "Delete email from all mailboxes",
            "Block sender domain",
            "Isolate affected endpoint",
            "Run full antivirus/EDR scan",
            "Collect process execution logs",
            "Block attachment hash across environment"
        ],

        "User Clicked Malicious Phishing Link": [
            "Delete email from all mailboxes",
            "Block sender domain",
            "Block malicious URLs at proxy/firewall",
            "Monitor user browser and login activity"
        ],

        # ===== MEDIUM =====
        "Malware Delivery Attempt (Attachment Not Opened)": [
            "Delete email from all mailboxes",
            "Block sender domain",
            "Block attachment hash",
            "Warn user not to open attachment"
        ],

        "Phishing Link Clicked (No Known Malicious Verdict Yet)": [
            "Delete email from all mailboxes",
            "Block sender domain",
            "Investigate URL reputation",
            "Monitor user activity for 24 hours"
        ],

        "Spoofed Sender Phishing Attempt": [
            "Delete email from all mailboxes",
            "Block sender domain",
            "Review mail gateway spoof protection rules"
        ],

        "New Domain Phishing Lure": [
            "Delete email from all mailboxes",
            "Block sender domain",
            "Add domain to watchlist"
        ],

        "Malicious URL Detected (No Interaction)": [
            "Delete email from all mailboxes",
            "Block malicious URLs",
            "Block sender domain"
        ],

        # ===== LOW =====
        "Suspicious Email Indicators": [
            "Delete email from all mailboxes",
            "Mark sender as suspicious for monitoring"
        ],
    }

    # Default safe response
    default_actions = [
        "Delete email from all mailboxes",
        "Block sender domain"
    ]

    actions = RESPONSE_PLAYBOOK.get(classification, default_actions)

    case["response"] = actions
    return case