import streamlit as st
from app.main import run_pipeline
import pandas as pd
st.set_page_config(page_title="Phishing Investigation Agent", layout="wide")

# ------------------ CSS ------------------
st.markdown("""
<style>
body {
    background-color: #0e1117;
    color: #e6edf3;
}
.alert-card {
    background-color: #161b22;
    padding: 18px;
    border-radius: 12px;
    margin-bottom: 18px;
    border: 1px solid #30363d;
}
.metric-box {
    background-color: #1A1F26;
    padding: 12px;
    border-radius: 10px;
    text-align: center;
    border: 1px solid #30363d;
    color: #c9d1d9;
}
.metric-title {
    font-size: 14px;
    color: #F2F2F2;
}
.metric-value {
    font-size: 22px;
    font-weight: bold;
}
</style>
""", unsafe_allow_html=True)

# ------------------ HEADER ------------------
st.title("Phishing Investigation Agent")
st.caption("SOC L1 Triage Dashboard")

# ------------------ LOAD CASES ------------------
cases = run_pipeline()   # <-- your real pipeline


# ------------------ SIDEBAR ------------------
st.sidebar.title("Alerts")
# st.sidebar.write(f"Total Alerts: **{len(cases)}**")

# ------------------ MAIN VIEW ------------------

for case in cases:
    with st.container():
        # st.markdown('<div class="alert-card">', unsafe_allow_html=True)

        # -------- TITLE --------
        st.subheader(f"Case ID: {case.get('case_id')}")
        st.markdown(f"**Title:** {case.get('alert_title','Suspicious Email Detected')}")

        # -------- SUMMARY (LLM) --------
        st.markdown(f"**Summary:** {case.get('summary','No summary available')}")

        col1, col2 = st.columns(2)

        # Basic Details Table (Table 1)
        with col1:
            st.markdown("**Email Details**")
            email = case.get("email_evidence", {})
            
            basic_details = {
                "Sender Email": email.get("sender_email", "N/A"),
                "Recipient Email(s)": ", ".join(email.get("recipient_emails", ["N/A"])),
                "Subject": email.get("subject", "N/A"),
                "urls": "",
                "Attachments": ""
            }

            urls = case.get("url_click_evidence", [])
            for url in urls:
                basic_details["urls"] += url.get("url", "") + ", "
            attachments = case.get("attachment_evidence", [])
            for attachment in attachments:
                basic_details["Attachments"] += attachment.get("filename", "") + ", "
            
            # Display basic details in table format
            st.table(basic_details)

        # User Interaction Details Table (Table 2)
        with col2:
            st.markdown("**User Interaction Details**")

            interaction_data = []

            user_interaction = case.get("user_interaction_evidence", {})

            email_delivered = user_interaction.get("email_delivered", "N/A")
            link_clicked = user_interaction.get("link_clicked", "N/A")
            attachment_opened = user_interaction.get("attachment_opened", "N/A")
            clicked_urls = user_interaction.get("clicked_urls", [])
            opened_attachments = user_interaction.get("opened_attachments", [])

            # Adding rows for user interaction
            interaction_data.append({
                "Action": "Email Delivered",
                "Status": email_delivered
            })
            interaction_data.append({
                "Action": "Link Clicked",
                "Status": link_clicked
            })
            if link_clicked:
                for url in clicked_urls:
                    for url in clicked_urls:
                        interaction_data.append({
                            "Action": "Clicked URL",
                            "Status": True if url else False
                        })
            interaction_data.append({
                "Action": "Attachment Opened",
                "Status": attachment_opened
            })
            if attachment_opened:
                for attachment in opened_attachments:
                    interaction_data.append({
                        "Action": "Opened Attachment",
                        "Status": attachment
                    })

            # Displaying the table
            st.table(interaction_data)

        # -------- METRICS --------
        c1, c2, c3, c4 = st.columns(4)

        # Column 1: Classification
        with c1:
            st.markdown(f"""
            <div class="metric-box">
                <div class="metric-title">Classification</div>
                <div class="metric-value">{case.get("decision", {}).get('classification')}</div>
            </div>
            """, unsafe_allow_html=True)

        # Column 2: Risk Score
        with c2:
            st.markdown(f"""
            <div class="metric-box">
                <div class="metric-title">Risk Score</div>
                <div class="metric-value">{case.get('risk', {}).get('score',70)}</div>
            </div>
            """, unsafe_allow_html=True)

        # Column 3: Severity
        with c3:
            st.markdown(f"""
            <div class="metric-box">
                <div class="metric-title">Severity</div>
                <div class="metric-value">{case.get('risk', {}).get('level', 'Low')}</div>
            </div>
            """, unsafe_allow_html=True)

        # Column 4: Confidence
        with c4:
            st.markdown(f"""
            <div class="metric-box">
                <div class="metric-title">Model Confidence</div>
                <div class="metric-value">{case.get('risk', {}).get('breakdown', {} ).get('confidence', 0):.2f}</div>
            </div>
            """, unsafe_allow_html=True)

        # Divider for better layout
        st.divider()

        
        # -------- TABS --------
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "Network Indicators",
            "Malware File Indicators",
            "IOCs",
            "Response Actions",
            "Raw Evidence"
        ])


        # ---- NETWORK INDICATORS ----
        with tab1:
            network_rows = []
            for item in case.get("url_click_evidence", []):
                network_rows.append({
                    "IP Address": item.get("ip_address"),
                    "URL": item.get("url"),
                    "Click Action": item.get("click_action")
                })
            st.table(network_rows)

        # ---- MALWARE FILE INDICATORS ----
        with tab2:
            file_rows = []
            for item in case.get("attachment_evidence", []):
                file_rows.append({
                    "IP Address": item.get("ip"),
                    "Attachment": item.get("filename"),
                    "Click Action": item.get("action")
                })
            st.table(file_rows)

        # ---- IOC TAB ----
        with tab3:
            iocs = case.get("iocs", {})

            col1, col2 = st.columns(2)

            with col1:
                st.markdown("#### Domains")
                st.table([{"Domain": d} for d in iocs.get("domains", [])])

                st.markdown("#### Sender Emails")
                st.table([{"Sender Email": s} for s in iocs.get("sender_emails", [])])

            with col2:
                st.markdown("#### URLs")
                st.table([{"URL": u} for u in iocs.get("urls", [])])

                st.markdown("#### IP Addresses")
                st.table([{"IP Address": ip} for ip in iocs.get("ip_addresses", [])])

            if iocs.get("file_hashes"):
                st.markdown("#### File Hashes")
                st.table([{"File Hash": h} for h in iocs.get("file_hashes", [])])

        with tab4:
            st.markdown("### Recommended Response Actions")

            responses = case.get("response", [])

            if responses:
                table_data = []
                for idx, action in enumerate(responses, start=1):
                    table_data.append({
                        "Action": action
                    })
                df = pd.DataFrame(table_data)

                # Display the table without the auto-generated index
                st.table(df.set_index(pd.Index(range(1, len(df) + 1)))) 
            else:
                st.info("No response actions available for this case.")

        # ---- RAW ----
        with tab5:
            st.json(case)