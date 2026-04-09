import json
from llm.ollama_client import query_ollama


def generate_summary(case):

    context = {
        "email": case.get("email_evidence", {}),
        "attack_chain": case.get("decision", {}).get("attack_chain", []),
        "attack_stage": case.get("decision", {}).get("attack_stage", ""),
        "risk": case.get("risk", {}),
        "ioc": case.get("iocs", {}),
    }

    prompt = f"""
            You are a SOC analyst.

            Summarize the following phishing investigation in 3-4 concise sentences.

            Focus on:
            - What happened
            - What the user did
            - What the attacker achieved
            - Risk level

            Data:
            {json.dumps(context, indent=2)}

            Return only plain text summary.
            """

    try:
        response = query_ollama(prompt)
        case["summary"] = response.strip()
        return case
    except Exception as e:
        print(f"Summary generation failed: {e}")
        return "Summary not available."