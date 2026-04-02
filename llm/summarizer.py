from llm.ollama_client import query_ollama

def generate_summary(case):
    prompt =f"""
        You are a SOC Analyst

        Analyze the following phishing case:
            Classification: {case['decision']['classification']}
            URL Analysis: {case['url_analysis']}
            Spoofing Logs: {case['spoofing']}
            Identity Logs: {case['identity']}
            Attachment Analysis: {case['attachment_analysis']}
            User Interaction with mail: {case['user_interaction']}

        Provide a clear technical summary

    """

    summary = query_ollama(prompt)

    case['summary'] = summary

    return case

def generate_summary2(case):
    
    prompt = f"""
    Summarize this security incident for a non-technical executive.

    Classification: {case['decision']['classification']}
    Severity: {case['decision']['severity']}
    
    Keep it simple and clear.
    """
    
    exec_summary = query_ollama(prompt)
    
    case["summary2"] = exec_summary
    
    return case