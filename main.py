from modules.parser import load_and_normalize
from modules.enrichment import enrich
from core.orchestrator.pipeline import initialize_case

def run():
    alerts = load_and_normalize("data/email_logs.json")

    print("==Normalized OUTPUT==\n")

    for alert in alerts:
        for key, value in alert.items():
            print(f"{key}:{value}")
        case = initialize_case(alert)
        case = enrich(case)
        for key, value in case.items():
            print(f"{key}:{value}")
        
        
    

if __name__ == "__main__":
    run()