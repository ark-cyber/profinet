from scapy.all import rdpcap, Ether

import joblib

# === Load model and encoders ===
model = joblib.load(r"rf_model.pkl")
le_src = joblib.load(r"src_mac_encoder.pkl")
le_dst = joblib.load(r"dst_mac_encoder.pkl")

def classify_packet(pkt):
    if not pkt.haslayer(Ether):
        return "Not an Ethernet packet"

    try:
        src_mac = pkt[Ether].src
        dst_mac = pkt[Ether].dst
        pkt_size = len(pkt)

        # Encode MACs
        try:
            src_encoded = le_src.transform([src_mac])[0]
        except:
            src_encoded = -1

        try:
            dst_encoded = le_dst.transform([dst_mac])[0]
        except:
            dst_encoded = -1

        features = [[pkt_size, src_encoded, dst_encoded]]
        prediction = model.predict(features)[0]
        label = "Normal" if prediction == 0 else "Anomaly"

        return {
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "size": pkt_size,
            "prediction": int(prediction),
            "label": label
        }

    except Exception as e:
        return f"Error processing packet: {e}"

# === Load packet from file ===
def main():
    # Replace with your .pcap file path
    packets = rdpcap(r"Initialisierung S7-Siemens.pcap")

    for i, pkt in enumerate(packets):
        result = classify_packet(pkt)
       # print(f"\nPacket #{i + 1}")
        print(result)

if __name__ == "__main__":
    main()
