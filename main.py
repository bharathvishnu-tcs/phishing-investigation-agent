from modules.parser import load_and_normalize
from modules.enrichment import enrich

def run():
    alerts = load_and_normalize("data/email_logs.json")

    print("==Normalized OUTPUT==\n")

    for alert in alerts:
        for key, value in alert.items():
            print(f"{key}:{value}")
        

    # for alert in alerts:
    #     case = enrich(alert)
    #     for key,value in case.items():
    #         print(f"{key}:{value}")

if __name__ == "__main__":
    run()