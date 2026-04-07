from llm.ollama_client import query_ollama

def generate_reasoning(case):
    prompt = f"""
        You are a SOC analyst.

        STRICTLY analyze ONLY the given data.

        Do NOT assume anything outside the input.

        Data:
        URL Analysis: {case['url_click_evidence']}
        Spoofing: {case['spoofing']}
        Header: {case['header_analysis']}
        User Interaction: {case['user_interaction']}
        Identity: {case['identity']}
        Endpoint: {case['endpoint_evidence']}

        Explain step-by-step why this is classified as:
        {case['decision']['classification']}

        Only describe facts present in data.
        Do not exaggerate or assume.
        """

    reasoning = query_ollama(prompt)

    case["llm_reasoning"] = reasoning

    return case