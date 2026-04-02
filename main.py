from modules.parser import load_and_normalize
from modules.enrichment import enrich
from core.orchestrator.pipeline import initialize_case
from modules.url_intel import analyze_url
from modules.spoofing_analysis import analyze_spoofing
from modules.user_interaction import analyze_user_interaction
from modules.identity_analysis import analyze_identity
from modules.endpoint_analysis import analyze_endpoint

def run():
    alerts = load_and_normalize("data/email_logs.json")

    

    for alert in alerts:
        print("==Normalized OUTPUT==\n")
        for key, value in alert.items():
            print(f"{key}:{value}")
        case = initialize_case(alert)
        case = enrich(case)
        case = analyze_url(case)
        case = analyze_spoofing(case)
        case = analyze_user_interaction(case)
        case = analyze_endpoint(case)
        case = analyze_identity(case)
        print("\nEnriched OUTPUT")
        for key, value in case.items():
            print(f"{key}:{value}")
        
        
    

if __name__ == "__main__":
    run()