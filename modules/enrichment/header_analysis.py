def analyze_header(case):
    raw_log = case.get("raw_log",{})
    header_analysis = {
        "spf":raw_log.get("spf_result","unknown"),
        #can add more 
        "is_suspicious": False,
        "reasons": []
    }

    if header_analysis["spf"] == "fail":
        header_analysis["is_suspicious"] = True
        header_analysis["reasons"].append("SPF Failed")

    case["header_analysis"] = header_analysis

    return case
