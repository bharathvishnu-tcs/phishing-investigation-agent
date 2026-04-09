import json
from llm.ollama_client import query_ollama   # your existing LLM wrapper


def llm_classify(context: dict):
    """
    Uses LLM to classify phishing case and return structured SOC-style output.
    """

    prompt = f"""
You are a cybersecurity analyst investigating a potential phishing incident.

Analyze the following structured data:

{json.dumps(context, indent=2)}

Your task is to determine:
1. classification: (Phishing / Attempted Phishing / Legitimate)
2. attack_stage: (Initial Access / User Interaction / Post-Compromise)
3. attack_chain: list of stages from:
   ["Initial Access", "User Interaction", "Execution", "Credential Theft",
    "Account Takeover", "Persistence", "Data Exfiltration"]
4. confidence: float between 0 and 1
5. reasoning: list of short bullet points explaining the decision

IMPORTANT:
- Return ONLY valid JSON
- Do NOT include explanations outside JSON
- Keep reasoning concise (max 5 points)
"""

    try:
        response = query_ollama(prompt)

        # 🔹 Clean response (sometimes LLM adds text)
        start = response.find("{")
        end = response.rfind("}") + 1
        clean_json = response[start:end]

        result = json.loads(clean_json)

        # 🔹 Basic validation
        required_keys = ["classification", "attack_stage", "confidence"]
        if not all(k in result for k in required_keys):
            return None

        return result

    except Exception as e:
        print(f"LLM classification failed: {e}")
        return None