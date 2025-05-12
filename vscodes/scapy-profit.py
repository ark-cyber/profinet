#Profinet is an industrial Ethernet protocol — it sits directly over Ethernet (not always over IP).
#So we have to slightly change the analyzer to:
#Read Ethernet frames.
#Look for Profinet traffic, usually identified by:
#EtherType 0x8892 (for Profinet RT Class 1 - Real-Time Communication)
#Other Profinet types (like DCP, etc.) have specific signatures too.

from scapy.all import rdpcap, Ether
from collections import Counter

def analyze_profinet_pcap(file_path):
    packets = rdpcap(file_path)

    print(f"Total packets captured: {len(packets)}\n")

    profinet_packets = []
    other_packets = []

    for packet in packets:
        if packet.haslayer(Ether):
            eth_type = packet[Ether].type
            if eth_type == 0x8892:
                profinet_packets.append(packet)
            else:
                other_packets.append(packet)

    print(f"Profinet packets detected: {len(profinet_packets)}")
    print(f"Other packets: {len(other_packets)}\n")

    if profinet_packets:
        print("First few Profinet packets summary:\n")
        for pkt in profinet_packets[:5]:
            pkt.show()
            print("-" * 50)

if __name__ == "__main__":
    file_path = r"C:\Users\sebae_a\OneDrive - University of Warwick\Academic Private\Supervision\Summer Pedagogical research\Summer 25\vscodes\Initialisierung S7-Siemens.pcap"  # Update your path here
    analyze_profinet_pcap(file_path)
