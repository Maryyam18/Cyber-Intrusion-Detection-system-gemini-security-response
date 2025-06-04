import streamlit as st
import joblib
import pandas as pd
import requests


GEMINI_API_KEY = "AIzaSyDgGFIp97RuKkr8PijMkfHigFdDWSTVCIg"


GEMINI_URL = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={GEMINI_API_KEY}"


model = joblib.load("cyber_intrusion_model.pkl")


st.set_page_config(page_title="Cyber Intrusion Detection", layout="wide")  

st.markdown("""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@600;700;900&display=swap');

        .stApp {
            background: linear-gradient(135deg, #e0f7ff 0%, #c2e9fb 100%);
            color: #1b1b1b;
            font-family: 'Poppins', sans-serif;
        }

        /* Project Title */
        .css-18e3th9 {
            color: #0c3c78;
            font-weight: 900;
            font-size: 60px;
            text-align: center !important;
            margin-left: auto !important;
            margin-right: auto !important;
        }

        /* Subheading (first letter capital) */
        .stSubheader {
            font-size: 22px;
            font-weight: 500;
            color: #084078;
            text-transform: capitalize;
            text-align: center !important;
            margin-left: auto !important;
            margin-right: auto !important;
            width: fit-content;
        }

        /* Enlarging input field labels */
        label {
            font-size: 28px !important;
            font-weight: 800 !important;
            color: #042e60 !important;
            margin-bottom: 12px;
            display: block;
        }

        /* Input Fields */
        input[type="number"],
        div[role="combobox"] > div {
            font-size: 24px !important;
            padding: 18px 22px !important;
            border-radius: 12px;
            border: 2px solid #a7c7e7;
            background-color: #ffffff;
            color: black !important;
        }

        /* Buttons */
        div.stButton > button {
            background-color: #0c3c78;
            color: white;
            font-weight: 800;
            padding: 22px 48px;
            border-radius: 16px;
            font-size: 26px;
            box-shadow: 0 4px 12px rgba(12,60,120,0.5);
            transition: background-color 0.3s ease;
            width: 100%;
            max-width: 380px;
            margin-top: 40px;
        }

        div.stButton > button:hover {
            background-color: #084078;
            box-shadow: 0 6px 16px rgba(8,64,120,0.7);
        }

        .prediction-box {
            font-size: 30px;
            font-weight: bold;
            padding: 24px;
            border-radius: 16px;
            text-align: center;
            width: 98%;
        }

        .success-box {
            background-color: #007acc;
            color: #ffffff;
        }

        .error-box {
            background-color: #dc3545;
            color: #ffffff;
        }

        /* Gemini response box - darkened background but same tone */
        .gemini-box {
            background: #184a7d;  /* Darker blue */
            color: #d2efff;       /* Light text to contrast */
            font-size: 26px;
            font-weight: bold;
            padding: 24px;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
            text-align: center;
            width: 98%;
        }
    </style>
""", unsafe_allow_html=True)

# App Title
st.title("🌍 Cyber Intrusion Detection System")
st.subheader("Enter network activity details below to predict security threats.")


# Input Fields Section
st.subheader("Network Data Input")
network_packet_size = st.number_input("Network Packet Size", min_value=0, format="%d")
protocol_type = st.selectbox("Protocol Type", ["TCP", "UDP"])
login_attempts = st.number_input("Login Attempts", min_value=0, format="%d")
session_duration = st.number_input("Session Duration (seconds)", min_value=0, format="%d")
encryption_used = st.selectbox(" Encryption Type", ["DES", "AES"])
ip_reputation_score = st.number_input("IP Reputation Score (0 to 1)", min_value=0.0, max_value=1.0, format="%.2f")
failed_logins = st.number_input("Failed Login Attempts", min_value=0, format="%d")
browser_type = st.selectbox("Browser Type", ["Chrome", "Firefox", "Edge", "Unknown"])
unusual_time_access = st.selectbox("Unusual Time Access", [0, 1])

#Encode categorical inputs
protocol_type = 0 if protocol_type == "TCP" else 1
encryption_used = 0 if encryption_used == "DES" else 1
browser_type = {"Chrome": 0, "Firefox": 1, "Edge": 2, "Unknown": 3}[browser_type]

# Detect Intrusion & Auto Gemini Response
if st.button(" DETECT INTRUSION"):
    input_data = pd.DataFrame([[network_packet_size, protocol_type, login_attempts,
                                session_duration, encryption_used, ip_reputation_score,
                                failed_logins, browser_type, unusual_time_access]],
                              columns=["network_packet_size", "protocol_type", "login_attempts",
                                       "session_duration", "encryption_used", "ip_reputation_score",
                                       "failed_logins", "browser_type", "unusual_time_access"])
    
    prediction = model.predict(input_data)[0]
    result = "🚨 INTRUSION DETECTED! IMMEDIATE ACTION REQUIRED!" if prediction == 1 else "✅ NORMAL ACTIVITY. NO THREATS DETECTED."
    
    box_class = "error-box" if prediction == 1 else "success-box"
    st.markdown(f'<div class="prediction-box {box_class}">{result}</div>', unsafe_allow_html=True)

    # Gemini AI Security Insight
    st.subheader("💡 Gemini Ai Security Insight")

    gemini_payload = {
        "contents": [
            {"parts": [{"text": f"Cyber intrusion detection result: {result}. Recommend security actions."}]}
        ]
    }

    headers = {"Content-Type": "application/json"}
    response = requests.post(GEMINI_URL, json=gemini_payload, headers=headers)

    if response.status_code == 200:
        gemini_reply = response.json().get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "⚠️ No response received.")
        st.markdown(f'<div class="gemini-box">{gemini_reply}</div>', unsafe_allow_html=True)
    else:
        st.error(f"⚠️ Gemini API Error: {response.status_code} - {response.text}")
