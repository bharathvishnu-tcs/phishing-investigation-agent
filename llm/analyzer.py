from llm.ollama_client import query_ollama

def generate_reasoning(case):
    prompt = f"""
        Explain why this alert is classified as {case['decision']['classification']}

        Provide step by step reasoning based on 
            - Header Analysis
            - URL Analysis
            - Spoofing
            - Attachment Analysis
            - User Interaction
            - Identity compromise
    """

    reasoning = query_ollama(prompt)

    case["llm_reasoning"] = reasoning

    return case