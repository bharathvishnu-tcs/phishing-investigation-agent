from modules.parser import load_and_normalize
from modules.enrichment.enrichment import enrich
from core.orchestrator.pipeline import initialize_case
from modules.enrichment.url_intel import analyze_url
from modules.enrichment.spoofing_analysis import analyze_spoofing
from modules.enrichment.user_interaction import analyze_user_interaction
from modules.enrichment.identity_analysis import analyze_identity
from modules.enrichment.endpoint_analysis import analyze_endpoint
from modules.enrichment.attachment_analysis import analyze_attachments
from modules.classification.classifier import classify
from modules.ioc.collect_ioc import collect_ioc
from modules.ioc.ioc_sweep import ioc_sweep
from modules.decision.respond import respond
from llm.analyzer import generate_reasoning
from llm.summarizer import generate_summary, generate_summary2

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
        case = analyze_attachments(case)
        case = classify(case)
        case = respond(case)
        case = collect_ioc(case)
        case = ioc_sweep(case)
        case = generate_summary(case)
        case = generate_summary2(case)
        case = generate_reasoning(case)

        print("\n===Enriched OUTPUT==\n")
        for key, value in case.items():
            print(f"{key}:{value}")
        
        
    

if __name__ == "__main__":
    run()