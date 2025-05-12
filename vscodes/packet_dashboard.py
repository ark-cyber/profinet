
#pip install streamlit pandas scapy joblib

import streamlit as st
from scapy.all import rdpcap, Ether
import pandas as pd
import joblib

# Load model and encoders
model = joblib.load("rf_model.pkl")
le_src = joblib.load("src_mac_encoder.pkl")
le_dst = joblib.load("dst_mac_encoder.pkl")

# Upload PCAP file
st.title("Packet Classifier Dashboard")
uploaded_file = st.file_uploader("Upload a PCAP file", type=["pcap"])

def classify_packet(pkt):
    if not pkt.haslayer(Ether):
        return None

    src = pkt[Ether].src
    dst = pkt[Ether].dst
    size = len(pkt)

    try:
        src_encoded = le_src.transform([src])[0]
    except:
        src_encoded = -1
    try:
        dst_encoded = le_dst.transform([dst])[0]
    except:
        dst_encoded = -1

    features = [[size, src_encoded, dst_encoded]]
    prediction = model.predict(features)[0]
    label = "Normal" if prediction == 0 else "Anomaly"

    return {"src": src, "dst": dst, "size": size, "status": label}

if uploaded_file:
    packets = rdpcap(uploaded_file)
    data = []

    for pkt in packets:
        result = classify_packet(pkt)
        if result:
            data.append(result)

    df = pd.DataFrame(data)

    # Display table
    st.subheader("Packet Summary")
    st.dataframe(df)

    # Pie chart
    st.subheader("Traffic Breakdown")
    status_counts = df['status'].value_counts()
    st.plotly_chart(status_counts.plot.pie(autopct='%1.1f%%', figsize=(4, 4), ylabel="").figure)

    # Line chart
    st.subheader("Packet Size Over Time")
    st.line_chart(df['size'])

    # Filter
    st.subheader("Anomalies Only")
    st.dataframe(df[df['status'] == "Anomaly"])

##streamlit run c:/Users/sebae_a/OneDrive - University of Warwick/Academic Private/Supervision/Summer Pedagogical research/Summer 25/vscodes/packet_dashboard.py