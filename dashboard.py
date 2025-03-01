import streamlit as st
import pandas as pd
import requests
import re

st.title("🛡️ CyberRisk AI")
st.markdown(
    """
    **CyberRisk AI** is an AI-powered vulnerability risk analyzer that helps organizations prioritize cybersecurity threats using machine learning and NVD data. 
    It automates risk assessment by analyzing **CVSS scores, CWE identifiers, and vulnerability descriptions**, enabling **faster and smarter security decision-making**.
    
    ### 🔍 Key Features
    - 📂 **Bulk Vulnerability Processing** – Upload CSV files with CVEs and get instant risk prioritization.
    - 🔢 **CVSS-Based Risk Scoring** – Uses **CVSS v4.0** to assign severity levels.
    - 🛑 **CWE-Aware Classification** – Considers CWE categories for better vulnerability insights.
    - 📊 **Adaptive Learning** – Machine learning enhances risk predictions beyond static CVSS scores.
    - 🌍 **Web-Based Interface** – Accessible via a **Streamlit dashboard** for ease of use.
    
    🚀 **CyberRisk AI helps security teams focus on the most critical threats first!**
    """
)
st.write("Upload a CSV file or enter individual details to analyze vulnerabilities and get risk-based prioritization.")

# File Uploader
uploaded_file = st.file_uploader("📂 Choose a CSV file", type=["csv"])

if uploaded_file is not None:
    # Read CSV
    df = pd.read_csv(uploaded_file)

    # Ensure required columns exist
    required_columns = {"Description", "CVSS_Score", "CWE"}
    if not required_columns.issubset(df.columns):
        st.error("⚠️ CSV must have 'Description', 'CVSS_Score', and 'CWE' columns.")
    else:
        st.write("### 📊 Uploaded Data Preview:")
        st.dataframe(df.head())  # Show preview of uploaded data

        # Fill missing values with defaults
        df["CVSS_Score"] = df["CVSS_Score"].fillna(0.0)  # Default to 0.0 if missing
        df["Description"] = df["Description"].fillna("No description provided")  # Default text
        df["CWE"] = df["CWE"].fillna("Unknown CWE")  # Default CWE category

        # Send the data to Flask API
        st.write("### 🔄 Processing Data...")
        response = requests.post("http://127.0.0.1:5000/predict_bulk", json=df.to_dict(orient="records"))

        if response.status_code == 200:
            results = pd.DataFrame(response.json())  # Convert API response to DataFrame
            st.write("### ✅ Prioritized Vulnerabilities:")
            st.dataframe(results)  # Display prioritized results
        else:
            st.error("❌ Error processing the file. Please check API connection.")

# Individual Entry Form
st.write("---")
st.write("### 🎯 Predict Risk for a Single Vulnerability")

cvss_score = st.number_input("🔢 CVSS Score (0.0 - 10.0, optional)", min_value=0.0, max_value=10.0, step=0.1, format="%.1f")
cwe = st.text_input("🔍 CWE (Format: CWE-###, e.g., CWE-79, CWE-787, optional)", help="Enter CWE in format 'CWE-###'. No spaces.")
description = st.text_area("📝 Vulnerability Description (optional)", help="Provide a brief and clear description of the vulnerability.")

def validate_cwe(cwe_text):
    return bool(re.match(r'^CWE-\d+$', cwe_text)) if cwe_text else True

if st.button("🚀 Predict Risk Level"):
    filled_fields = sum(bool(field.strip()) for field in [str(cvss_score), cwe, description])
    if filled_fields < 2:
        st.warning("⚠️ At least two out of three fields (CVSS Score, CWE, Description) must be provided.")
    elif cwe and not validate_cwe(cwe.strip()):
        st.error("❌ Invalid CWE format. Use 'CWE-###' format (e.g., CWE-79, CWE-787).")
    else:
        input_data = {
            "Description": description.strip() if description.strip() else "No description provided",
            "CVSS_Score": cvss_score if cvss_score else 0.0,
            "CWE": cwe.strip() if cwe.strip() else "Unknown CWE"
        }
        response = requests.post("http://127.0.0.1:5000/predict", json=input_data)
        if response.status_code == 200:
            prediction = response.json()["Predicted_Risk_Level"]
            st.success(f"✅ Predicted Risk Level: {prediction}")
        else:
            st.error("❌ Failed to get prediction from API.")
