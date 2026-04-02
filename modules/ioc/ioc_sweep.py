def ioc_sweep(case):
    
    iocs = case.get("iocs", {})
    
    sweep_results = {
        "matches_found": False,
        "affected_users": [],
        "notes": []
    }
    
    # Simulation
    
    # Example: if malicious domain exists
    for domain in iocs.get("domains", []):
        if "login" in domain or "secure" in domain:
            sweep_results["matches_found"] = True
            sweep_results["affected_users"].extend([
                "user1@company.com",
                "user2@company.com"
            ])
            sweep_results["notes"].append(f"Domain {domain} seen across multiple users")
    
    case["ioc_sweep"] = sweep_results
    
    return case