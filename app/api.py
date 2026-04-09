from fastapi import FastAPI
from app.main import run_pipeline
from utils.formatter import format_output

app = FastAPI()

@app.get("/")
def home():
    return {
        "message": "Phishing Investigation API Running..."
    }

@app.post("/investigate")
def investigate():
    cases = run_pipeline()
    return cases