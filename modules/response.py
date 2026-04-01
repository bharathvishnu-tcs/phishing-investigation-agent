def generate_response(scenario):
    actions = []
    actions.append("Delete email from M365")
    actions.append("Block sender")

    if scenario == "Phishing":
        actions.append("Block URL")
    return actions