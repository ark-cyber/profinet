from scapy.all import rdpcap, Ether
import pandas as pd

def extract_profinet_features(file_path, output_csv):
    packets = rdpcap(file_path)

    print(f"Total packets captured: {len(packets)}\n")

    data = []

    for packet in packets:
        if packet.haslayer(Ether):
            eth_type = packet[Ether].type
            if eth_type == 0x8892:  # Profinet EtherType
                features = {
                    "timestamp": packet.time,
                    "packet_size": len(packet),
                    "src_mac": packet[Ether].src,
                    "dst_mac": packet[Ether].dst,
                    "ethertype": hex(eth_type)
                }
                data.append(features)

    # Create a DataFrame
    df = pd.DataFrame(data)
    
    # Show the first few rows
    print(df.head())

    # Save to CSV
    df.to_csv(output_csv, index=False)
    print(f"\nFeatures saved to {output_csv}")

if __name__ == "__main__":
    file_path = r"Initialisierung S7-Siemens.pcap"      # <-- Your pcap
    output_csv = r"C:\Users\sebae_a\OneDrive - University of Warwick\Academic Private\Supervision\Summer Pedagogical research\Summer 25\vscodes\output.csv"    # <-- Where to save the features
    extract_profinet_features(file_path, output_csv)
