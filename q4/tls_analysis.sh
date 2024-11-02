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

# Create output directory first
mkdir -p "$OUTPUT_DIR"
touch "$LOG_FILE"

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

# Setup environment
setup_environment() {
    # Export SSLKEYLOG variable for browsers to use
    export SSLKEYLOGFILE="$SSLKEYLOG_FILE"
    touch "$SSLKEYLOG_FILE"
}

# Capture traffic
capture_traffic() {
    log "Starting packet capture for $CAPTURE_DURATION seconds..." "$GREEN"

    # Get the actual interface name if not specified
    if [ "$CAPTURE_INTERFACE" = "eth0" ]; then
        CAPTURE_INTERFACE=$(ip route get 8.8.8.8 | awk '{print $5; exit}')
        log "Using interface: $CAPTURE_INTERFACE" "$GREEN"
    fi

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

# Display Results
display_results() {
    log "\nAnalysis Results Summary:" "$GREEN"

    # Display handshake metadata
    if [ -f "${OUTPUT_DIR}/handshake_metadata.txt" ]; then
        log "\nHandshake Metadata (first 5 lines):" "$GREEN"
        head -n 5 "${OUTPUT_DIR}/handshake_metadata.txt"
    fi

    # Display cipher suites
    if [ -f "${OUTPUT_DIR}/cipher_suites.txt" ]; then
        log "\nDetected Cipher Suites:" "$GREEN"
        cat "${OUTPUT_DIR}/cipher_suites.txt"
    fi

    # Display summary from detailed analysis
    if [ -f "${OUTPUT_DIR}/detailed_analysis.json" ]; then
        log "\nDetailed Analysis Summary:" "$GREEN"
        python3 -c "
import json
with open('${OUTPUT_DIR}/detailed_analysis.json') as f:
    data = json.load(f)
print(f'Client Hello Messages: {len(data[\"client_hello\"])}')
print(f'Server Hello Messages: {len(data[\"server_hello\"])}')
"
    fi
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
    display_results

    log "\nAnalysis completed. Results are in $OUTPUT_DIR" "$GREEN"
    log "Key files:" "$GREEN"
    log "- Handshake metadata: ${OUTPUT_DIR}/handshake_metadata.txt" "$GREEN"
    log "- Cipher suites: ${OUTPUT_DIR}/cipher_suites.txt" "$GREEN"
    log "- Detailed analysis: ${OUTPUT_DIR}/detailed_analysis.json" "$GREEN"
    log "- Raw capture: $PCAP_FILE" "$GREEN"
}

main "$@"
