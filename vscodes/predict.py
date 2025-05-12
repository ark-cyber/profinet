
#Capture Ethernet frames live using Scapy 🧲

#Extract features exactly like during training (packet size, MAC addresses) 📦

#Encode features properly using saved LabelEncoders 🔑

#Predict with the trained Random Forest model 🧠

#Print live predictions on screen

from scapy.all import sniff, Ether
import joblib
import pandas as pd

# Load model and encoders
model = joblib.load(r"rf_model.pkl")
le_src = joblib.load(r"rc_mac_encoder.pkl")
le_dst = joblib.load(r"dst_mac_encoder.pkl")

def process_packet(packet):
    if packet.haslayer(Ether):
        eth_type = packet[Ether].type
        if eth_type == 0x8892:  # Profinet EtherType
            try:
                src_mac = packet[Ether].src
                dst_mac = packet[Ether].dst
                packet_size = len(packet)

                # Encode MAC addresses (handle unseen MACs)
                try:
                    src_mac_encoded = le_src.transform([src_mac])[0]
                except:
                    src_mac_encoded = -1  # Unknown MAC
                try:
                    dst_mac_encoded = le_dst.transform([dst_mac])[0]
                except:
                    dst_mac_encoded = -1  # Unknown MAC

                # Create feature array
                features = [[packet_size, src_mac_encoded, dst_mac_encoded]]

                # Predict
                prediction = model.predict(features)[0]
                label = "Normal" if prediction == 0 else "Anomaly"

                print(f"[{label}] - Src: {src_mac} --> Dst: {dst_mac} | Size: {packet_size}")

            except Exception as e:
                print(f"Error processing packet: {e}")

def start_sniffing(interface):
    print(f"Starting live sniffing on {interface}...\nPress Ctrl+C to stop.")
    sniff(iface=interface, prn=process_packet, store=False)

if __name__ == "__main__":
    interface = "Ethernet"  # <-- Change to your real network interface name
    start_sniffing(interface)
