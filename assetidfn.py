from scapy.layers.l2 import Ether
from scapy.layers.l2 import ARP
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.all import rdpcap, Ether, ARP, IP, IPv6

from flask import Flask, jsonify, request, render_template
import os

app = Flask(__name__)

# Function to determine the network layer based on pcap analysis
def determine_network_layer(pcap_file):
    try:
        packets = rdpcap(pcap_file)

        # Initialize protocol counters
        layer_counts = {
            "Data Link Layer (Ethernet)": 0,
            "Network Layer (ARP)": 0,
            "Network Layer (IPv4)": 0,
            "Network Layer (IPv6)": 0,
            "Unknown": 0
        }

        # Loop through the packets and count occurrences of different protocols
        for packet in packets:
            if packet.haslayer(Ether):
                layer_counts["Data Link Layer (Ethernet)"] += 1
            elif packet.haslayer(ARP):
                layer_counts["Network Layer (ARP)"] += 1
            elif packet.haslayer(IP):
                layer_counts["Network Layer (IPv4)"] += 1
            elif packet.haslayer(IPv6):
                layer_counts["Network Layer (IPv6)"] += 1
            else:
                layer_counts["Unknown"] += 1

        return layer_counts

    except Exception as e:
        return f"Error: {e}"
    
@app.route('/')
def index():
    return render_template('upload.html')

# Flask route to handle the analysis request
@app.route('/analyze_pcap', methods=['POST'])
def analyze_pcap():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    pcap_file = request.files['file']
    if pcap_file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    # Save the uploaded pcap file temporarily for analysis
    pcap_file.save('temp.pcap')

    # Determine the network layer
    network_layer = determine_network_layer('temp.pcap')

    # Remove the temporary pcap file
    os.remove('temp.pcap')

    return jsonify({'network_layer': network_layer}), 200

if __name__ == '__main__':
    app.run(debug=True)
