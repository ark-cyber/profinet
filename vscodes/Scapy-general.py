from scapy.all import rdpcap
from collections import Counter


def analyze_pcap(file_path):
    packets = rdpcap(file_path)

    print(f"Total packets captured: {len(packets)}\n")

    protocols_counter = Counter()
    src_ips = Counter()
    dst_ips = Counter()

    for packet in packets:
        # Count protocols
        if packet.haslayer('IP'):
            proto = packet['IP'].proto
            protocols_counter[proto] += 1

            src_ips[packet['IP'].src] += 1
            dst_ips[packet['IP'].dst] += 1
        elif packet.haslayer('ARP'):
            protocols_counter['ARP'] += 1
        else:
            protocols_counter['Other'] += 1

    # Print protocols
    print("Protocols seen:")
    for proto, count in protocols_counter.items():
        print(f"  Protocol {proto}: {count} packets")

    # Top talkers
    print("\nTop 5 Source IPs:")
    for ip, count in src_ips.most_common(5):
        print(f"  {ip}: {count} packets")

    print("\nTop 5 Destination IPs:")
    for ip, count in dst_ips.most_common(5):
        print(f"  {ip}: {count} packets")

if __name__ == "__main__":
   
    file_path = r"C:\Users\sebae_a\OneDrive - University of Warwick\Academic Private\Supervision\Summer Pedagogical research\Summer 25\vscodes\intro-wireshark-trace1.pcap"
    analyze_pcap(file_path)