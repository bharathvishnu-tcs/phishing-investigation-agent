def analyze_user_interaction(case):
    
    urls = case.get("url_analysis", [])
    
    #Needs to be changed
    interaction = {
        "email_delivered": True,
        "email_opened": True,
        "link_clicked": False,
        "attachment_opened": False
    }
  
    for url in urls:
        if url.get("is_malicious"):
            interaction["link_clicked"] = True
    
    case["user_interaction"] = interaction
    
    return case