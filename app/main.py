#Entry Point
import sys
import os
import logging
logging.basicConfig(level = logging.INFO)
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.parser import load_and_normalize
from modules.enrichment.enrichment import enrich
from modules.enrichment.header_analysis import analyze_header
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
from modules.risk.risk_engine import calculate_risk
from llm.analyzer import generate_reasoning
from llm.summarizer import generate_summary, generate_summary2

def run_pipeline():
    alerts = load_and_normalize("data/email_logs.json")
    
    for alert in alerts:
        # print("==Normalized OUTPUT==\n")
        # for key, value in alert.items():
        #     print(f"{key}:{value}")
    
        case = initialize_case(alert)
        modules = [
            ("enrichement",enrich),
            ("header_analysis",analyze_header),
            ("url_analysis",analyze_url),
            ("attachment_analysis",analyze_attachments),
            ("spoofing",analyze_spoofing),
            ("user_interaction",analyze_user_interaction),
            ("identity",analyze_identity),
            ("endpoint",analyze_endpoint),
            ("ioc_collection",collect_ioc),
            ("ioc_sweep",ioc_sweep),
            ("risk",calculate_risk),
            ("classification",classify),
            ("response",respond)
        ]

        for name,module in modules:
            try:
                logging.info(f"Running {name}")
                case = module(case)
            except Exception as e:
                logging.error(f"{name} failed : {e}")
        
        case = generate_summary(case)
        case = generate_summary2(case)
        case = generate_reasoning(case)

        return case
