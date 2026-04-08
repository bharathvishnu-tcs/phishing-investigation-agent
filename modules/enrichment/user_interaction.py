def analyze_user_interaction(case: dict) -> dict:
    """
    Correlates email delivery with user actions such as URL clicks
    and attachment interaction using real telemetry evidence.
    """

    email = case.get("email_evidence", {})
    url_clicks = case.get("url_click_evidence", [])
    attachments = case.get("attachment_evidence", [])

    interaction = {
        "email_delivered": False,
        "link_clicked": False,
        "clicked_urls": [],
        "attachment_opened": False,
        "opened_attachments": []
    }

    # Email delivered check
    if email.get("delivery_action", "").lower() == "delivered":
        interaction["email_delivered"] = True

    # URL click correlation
    for click in url_clicks:
        if click.get("clicked_through") or click.get("click_action", "").lower() == "allowed":
            interaction["link_clicked"] = True
            interaction["clicked_urls"].append(click.get("url"))

    # Attachment interaction correlation
    for att in attachments:
        if att.get("action_type") in ["FileOpened", "FileExecuted", "FileDownloaded"]:
            interaction["attachment_opened"] = True
            interaction["opened_attachments"].append(att.get("FileName"))

    case["user_interaction"] = interaction
    return case