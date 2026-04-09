import streamlit as st
import json
import random

st.set_page_config(page_title="Phishing Investigation Agent", layout="wide")

# ---- CUSTOM STYLING ----
st.markdown("""
    <style>
        .main {
            background-color: #0e1117;
            color: white;
        }
        .card {
            padding: 15px;
            border-radius: 10px;
            background-color: #161b22;
            margin-bottom: 10px;
        }
        .title {
            font-size: 20px;
            font-weight: bold;
        }
    </style>
""", unsafe_allow_html=True)

# ---- HEADER ----
st.title(" Phishing Investigation Agent")
st.caption("Real-time Email Threat Analysis Dashboard")

# ---- SIDEBAR ----
st.sidebar.header("Input Data")

input_type = st.sidebar.radio("Select Input Type", ["Paste JSON", "Upload File"])

data = None

if input_type == "Paste JSON":
    text = st.sidebar.text_area("Paste Email Log JSON")
    if text:
        try:
            data = json.loads(text)
        except:
            st.sidebar.error("Invalid JSON")

else:
    file = st.sidebar.file_uploader("Upload JSON", type=["json"])
    if file:
        data = json.load(file)

# ---- MOCK ENGINE ----
def generate_result(data):
    return {
        "classification": random.choice(["Phishing", "Suspicious", "Legitimate"]),
        "severity": random.choice(["High", "Medium", "Low"]),
        "risk_score": random.randint(30, 95),
        "reasons": [
            "Domain mismatch detected",
            "Suspicious link pattern",
            "Sender spoofing likely"
        ],
        "indicators": {
            "sender_domain": data.get("sender_domain", "unknown"),
            "ip_address": "185.23.45.12",
            "attachments": random.choice([True, False])
        }
    }

# ---- ANALYZE BUTTON ----
if st.sidebar.button("Run Analysis"):
    if not data:
        st.warning("Provide input first")
    else:
        result = generate_result(data)

        # ---- TOP METRICS ----
        col1, col2, col3 = st.columns(3)

        with col1:
            st.markdown('<div class="card"><div class="title">Classification</div>{}</div>'.format(result["classification"]), unsafe_allow_html=True)

        with col2:
            st.markdown('<div class="card"><div class="title">Severity</div>{}</div>'.format(result["severity"]), unsafe_allow_html=True)

        with col3:
            st.markdown('<div class="card"><div class="title">Risk Score</div>{}</div>'.format(result["risk_score"]), unsafe_allow_html=True)

        # ---- RISK BAR ----
        st.subheader("Risk Level")
        st.progress(result["risk_score"] / 100)

        # ---- TWO COLUMN LAYOUT ----
        left, right = st.columns(2)

        with left:
            st.markdown("### Email Indicators")
            st.json(result["indicators"])

        with right:
            st.markdown("### Detection Insights")
            for r in result["reasons"]:
                st.write(f"• {r}")

        st.divider()

        # ---- RAW INPUT ----
        st.subheader("📄 Raw Email Data")
        st.json(data)

# ---- DEFAULT VIEW ----
else:
    st.info("Upload or paste email log data to begin analysis.")

    st.markdown("### 🧪 Sample Input")
    sample = {
        "sender_email": "support@micros0ft-security.com",
        "sender_domain": "micros0ft-security.com",
        "subject": "Verify your account immediately",
        "body": "Click the link to secure your account"
    }
    st.json(sample)