import json
def normalize_log(log):
    return {
        "process": log.get("process")
                    or log.get("FileName")
                    or log.get("process_name"),

        "command": log.get("command")
                    or log.get("InitiatingProcessCommandLine")
                    or log.get("cmdline"),

        "ip": log.get("ip")
                or log.get("IPAddress")
                or log.get("src_ip"),

        "user": log.get("user")
                or log.get("AccountName"),

        "device": log.get("device")
                  or log.get("DeviceName"),

        "timestamp": log.get("timestamp")
                      or log.get("TimeGenerated")
    }

RULES = [
    {
        "name": "external_url",
        "condition": lambda log: log["command"] and (
            "http://" in log["command"] or "https://" in log["command"]
        ),
        "score": 25,
        "flag": "External URL execution"
    },
    {
        "name": "encoded_command",
        "condition": lambda log: log["command"] and (
            "base64" in log["command"] or "encoded" in log["command"]
        ),
        "score": 30,
        "flag": "Encoded command"
    },
    {
        "name": "external_ip",
        "condition": lambda log: log["ip"] and not log["ip"].startswith(("10.", "192.168", "172.")),
        "score": 20,
        "flag": "External IP"
    },
    {
        "name": "phishing_pattern",
        "condition": lambda log: log["command"] and any(x in log["command"] for x in [
            "login-", "secure-", "verify-", "update-"
        ]),
        "score": 25,
        "flag": "Phishing-like pattern"
    }
]

def analyze_endpoint(case):
    with open("data/endpoint_telemetry_logs.json","r") as f:
        raw_log = json.load(f)
    raw_log = raw_log[case.get("log_index",0)]
    log = normalize_log(raw_log)

    score = 0
    flags = []

    for rule in RULES:
        try:
            if rule["condition"](log):
                score += rule["score"]
                flags.append(rule["flag"])
        except:
            continue

    if score >= 70:
        verdict = "High Risk"
    elif score >= 40:
        verdict = "Medium Risk"
    elif score > 0:
        verdict = "Low Risk"
    else:
        verdict = "Benign"

    evidence = {
            "normalized": log,
            "score": score,
            "flags": flags,
            "verdict": verdict
        }
    case["endpoint_evidence"] = evidence
    return case