from datetime import datetime
import json
from math import radians, sin, cos, sqrt, atan2

def calculate_distance_km(loc1, loc2):

    if loc1 != loc2:
        return 7000  # assume long distance needs to be changed
    return 0

def time_diff_hours(t1, t2):
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    d1 = datetime.strptime(t1, fmt)
    d2 = datetime.strptime(t2, fmt)
    return abs((d2 - d1).total_seconds()) / 3600


def analyze_identity(case):
    with open("data/impossible_travel_logs.json") as f:
        logs = json.load(f)
    with open("data/sign_in_logs.json") as f:
        logss = json.load(f)

    identity = {
        "credentials_submitted": False,
        # "multiple_failed_logins": False,
        "mfa_fatigue": False
    }

    impossible_travel = False


    login1 = logs.get("Login1")
    login2 = logs.get("Login2")

    if login1 and login2:
        distance = calculate_distance_km(
            login1.get("Location"),
            login2.get("Location")
        )

        time_diff = time_diff_hours(
            login1.get("Time"),
            login2.get("Time")
        )

        #can be adjusted
        if distance > 3000 and time_diff < 2:
            impossible_travel = False

    # needs to add failure multiple detection 


    auth_details = logss.get("AuthenticationDetails", [])

    mfa_push_count = sum(
        1 for a in auth_details
        if a.get("AuthenticationMethod") == "MFA Push"
    )

    if mfa_push_count >= 3:
        identity["mfa_fatigue"] = True


    risk = logss.get("RiskLevelDuringSignIn") or logss.get("RiskLevel")

    if risk and risk.lower() == "high":
        identity["credentials_submitted"] = True

    # -------------------------------
    case["sign_in_evidence"] = identity
    case["impossible_travel"] = impossible_travel

    return case