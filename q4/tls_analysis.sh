#!/bin/bash

# Exit on error
set -e

# Configuration
CAPTURE_INTERFACE="eth0" # Change this to your interface
CAPTURE_DURATION=60      # Capture duration in seconds
CAPTURE_FILTER="tcp port 443"
OUTPUT_DIR="/tmp/tls_analysis"
LOG_FILE="${OUTPUT_DIR}/analysis.log"
SSLKEYLOG_FILE="${OUTPUT_DIR}/sslkeylog.txt"
PCAP_FILE="${OUTPUT_DIR}/capture.pcap"
DECRYPTED_FILE="${OUTPUT_DIR}/decrypted.txt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log() {
    echo -e "${2:-$NC}$1${NC}" | tee -a "$LOG_FILE"
}

error() {
    log "$1" "$RED"
    exit 1
}

# Install dependencies
install_dependencies() {
    log "Installing dependencies..." "$GREEN"
    apt-get update
    apt-get install -y \
        tshark \
        python3 \
        python3-pip \
        curl \
        openssl

    # Install Python dependencies
    pip3 install scapy cryptography
}

# Create analysis directory
setup_environment() {
    mkdir -p "$OUTPUT_DIR"
    # Export SSLKEYLOG variable for browsers to use
    export SSLKEYLOGFILE="$SSLKEYLOG_FILE"
}

# Capture traffic
capture_traffic() {
    log "Starting packet capture for $CAPTURE_DURATION seconds..." "$GREEN"

    tshark -i "$CAPTURE_INTERFACE" \
        -f "$CAPTURE_FILTER" \
        -w "$PCAP_FILE" \
        -a duration:"$CAPTURE_DURATION" \
        2>>"$LOG_FILE"
}

# Analyze TLS handshake metadata
analyze_handshake() {
    log "Analyzing TLS handshake metadata..." "$GREEN"

    tshark -r "$PCAP_FILE" \
        -Y "tls.handshake" \
        -T fields \
        -e frame.number \
        -e frame.time \
        -e ip.src \
        -e ip.dst \
        -e tls.handshake.type \
        -e tls.handshake.version \
        -E header=y \
        >"${OUTPUT_DIR}/handshake_metadata.txt"

    # Extract cipher suites offered
    tshark -r "$PCAP_FILE" \
        -Y "tls.handshake.type == 1" \
        -T fields \
        -e tls.handshake.ciphersuite \
        >"${OUTPUT_DIR}/cipher_suites.txt"
}

# Python script for detailed TLS analysis
create_python_analyzer() {
    cat >"${OUTPUT_DIR}/tls_analyzer.py" <<'EOF'
from scapy.all import *
from scapy.layers.tls.all import *
import sys
import json

def analyze_pcap(pcap_file, output_file):
    packets = rdpcap(pcap_file)
    results = {
        'client_hello': [],
        'server_hello': [],
        'certificates': []
    }
    
    for pkt in packets:
        if TLS in pkt:
            if TLSClientHello in pkt:
                results['client_hello'].append({
                    'timestamp': float(pkt.time),
                    'version': pkt[TLSClientHello].version.name,
                    'random': pkt[TLSClientHello].random_bytes.hex()[:20] + '...'
                })
            elif TLSServerHello in pkt:
                results['server_hello'].append({
                    'timestamp': float(pkt.time),
                    'version': pkt[TLSServerHello].version.name,
                    'cipher_suite': pkt[TLSServerHello].cipher.name
                })
    
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python3 tls_analyzer.py <pcap_file> <output_file>")
        sys.exit(1)
    
    analyze_pcap(sys.argv[1], sys.argv[2])
EOF

    chmod +x "${OUTPUT_DIR}/tls_analyzer.py"
}

# Run the Python analyzer
run_python_analyzer() {
    log "Running detailed TLS analysis..." "$GREEN"
    python3 "${OUTPUT_DIR}/tls_analyzer.py" \
        "$PCAP_FILE" \
        "${OUTPUT_DIR}/detailed_analysis.json"
}

# Main function
main() {
    if [ "$EUID" -ne 0 ]; then
        error "Please run as root (sudo)"
    fi

    log "Starting TLS traffic analysis..." "$GREEN"

    install_dependencies
    setup_environment
    capture_traffic
    analyze_handshake
    create_python_analyzer
    run_python_analyzer

    log "Analysis completed. Results are in $OUTPUT_DIR" "$GREEN"
    log "Key files:" "$GREEN"
    log "- Handshake metadata: ${OUTPUT_DIR}/handshake_metadata.txt" "$GREEN"
    log "- Cipher suites: ${OUTPUT_DIR}/cipher_suites.txt" "$GREEN"
    log "- Detailed analysis: ${OUTPUT_DIR}/detailed_analysis.json" "$GREEN"
    log "- Raw capture: $PCAP_FILE" "$GREEN"
}

main "$@"
