#!/bin/bash

# Exit on error
set -e

# Configuration
CAPTURE_INTERFACE="eth0"
CAPTURE_DURATION=60
CAPTURE_FILTER="tcp port 443"
OUTPUT_DIR="/tmp/tls_analysis"
LOG_FILE="${OUTPUT_DIR}/analysis.log"
SSLKEYLOG_FILE="${OUTPUT_DIR}/sslkeylog.txt"
PCAP_FILE="${OUTPUT_DIR}/capture.pcap"
VENV_DIR="${OUTPUT_DIR}/venv"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Initialize logging
init_logging() {
    sudo mkdir -p "$OUTPUT_DIR"
    sudo touch "$LOG_FILE"
    sudo chmod 666 "$LOG_FILE"
}

init_logging

log() {
    echo -e "${2:-$NC}$1${NC}" | sudo tee -a "$LOG_FILE"
}

error() {
    log "$1" "$RED"
    exit 1
}

# Install system dependencies
install_system_dependencies() {
    log "Installing system dependencies..." "$GREEN"
    sudo apt-get update
    sudo apt-get install -y \
        tshark \
        python3-full \
        python3-venv \
        curl \
        openssl
}

# Setup Python virtual environment
setup_virtual_environment() {
    log "Setting up Python virtual environment..." "$GREEN"
    python3 -m venv "$VENV_DIR"
    # Activate virtual environment
    source "$VENV_DIR/bin/activate"
    # Install Python packages in virtual environment
    pip install scapy cryptography
}

# Capture traffic
capture_traffic() {
    log "Starting packet capture for $CAPTURE_DURATION seconds..." "$GREEN"

    if [ "$CAPTURE_INTERFACE" = "eth0" ]; then
        CAPTURE_INTERFACE=$(ip route get 8.8.8.8 | awk '{print $5; exit}')
        log "Using interface: $CAPTURE_INTERFACE" "$GREEN"
    fi

    sudo tshark -i "$CAPTURE_INTERFACE" \
        -f "$CAPTURE_FILTER" \
        -w "$PCAP_FILE" \
        -a duration:"$CAPTURE_DURATION"
}

# Analyze TLS handshake metadata
analyze_handshake() {
    log "Analyzing TLS handshake metadata..." "$GREEN"

    sudo tshark -r "$PCAP_FILE" \
        -Y "tls.handshake" \
        -T fields \
        -e frame.number \
        -e frame.time \
        -e ip.src \
        -e ip.dst \
        -e tls.handshake.type \
        -e tls.handshake.version \
        -E header=y |
        sudo tee "${OUTPUT_DIR}/handshake_metadata.txt"

    sudo tshark -r "$PCAP_FILE" \
        -Y "tls.handshake.type == 1" \
        -T fields \
        -e tls.handshake.ciphersuite |
        sudo tee "${OUTPUT_DIR}/cipher_suites.txt"
}

create_python_analyzer() {
    cat <<'EOF' | sudo tee "${OUTPUT_DIR}/tls_analyzer.py"
from scapy.all import *
from scapy.layers.tls.all import *
import sys
import json

def get_tls_version(version_int):
    """Convert TLS version number to string representation."""
    versions = {
        0x0300: "SSLv3",
        0x0301: "TLSv1.0",
        0x0302: "TLSv1.1",
        0x0303: "TLSv1.2",
        0x0304: "TLSv1.3"
    }
    return versions.get(version_int, f"Unknown (0x{version_int:04x})")

def get_cipher_suite(cipher_int):
    """Convert cipher suite number to string representation."""
    ciphers = {
        0x1301: "TLS_AES_128_GCM_SHA256",
        0x1302: "TLS_AES_256_GCM_SHA384",
        0x1303: "TLS_CHACHA20_POLY1305_SHA256",
        0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA"
    }
    return ciphers.get(cipher_int, f"Unknown (0x{cipher_int:04x})")

def analyze_pcap(pcap_file, output_file):
    packets = rdpcap(pcap_file)
    results = {
        'client_hello': [],
        'server_hello': [],
        'certificates': []
    }
    
    for pkt in packets:
        try:
            if TLS in pkt:
                if TLSClientHello in pkt:
                    hello = pkt[TLSClientHello]
                    cipher_suites = []
                    if hasattr(hello, 'ciphers'):
                        cipher_suites = [get_cipher_suite(c) for c in hello.ciphers]
                    
                    results['client_hello'].append({
                        'timestamp': float(pkt.time),
                        'version': get_tls_version(hello.version),
                        'cipher_suites': cipher_suites,
                        'random': hello.random_bytes.hex()[:20] + '...' if hasattr(hello, 'random_bytes') else 'N/A'
                    })
                elif TLSServerHello in pkt:
                    hello = pkt[TLSServerHello]
                    results['server_hello'].append({
                        'timestamp': float(pkt.time),
                        'version': get_tls_version(hello.version),
                        'cipher_suite': get_cipher_suite(hello.cipher) if hasattr(hello, 'cipher') else 'Unknown'
                    })
        except Exception as e:
            print(f"Error processing packet: {e}")
            continue

    # Add summary
    results['summary'] = {
        'total_client_hello': len(results['client_hello']),
        'total_server_hello': len(results['server_hello']),
        'protocol_versions': list(set(ch['version'] for ch in results['client_hello'] + results['server_hello'])),
        'unique_cipher_suites': list(set(cs for ch in results['client_hello'] for cs in ch['cipher_suites']))
    }

    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
        
    # Print summary to console
    print("\nTLS Analysis Summary:")
    print(f"Client Hello Messages: {results['summary']['total_client_hello']}")
    print(f"Server Hello Messages: {results['summary']['total_server_hello']}")
    print("\nProtocol Versions Used:")
    for version in results['summary']['protocol_versions']:
        print(f"- {version}")
    print("\nUnique Cipher Suites Offered:")
    for cipher in results['summary']['unique_cipher_suites']:
        print(f"- {cipher}")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python3 tls_analyzer.py <pcap_file> <output_file>")
        sys.exit(1)
    
    analyze_pcap(sys.argv[1], sys.argv[2])
EOF

    sudo chmod +x "${OUTPUT_DIR}/tls_analyzer.py"
}

run_python_analyzer() {
    log "Running detailed TLS analysis..." "$GREEN"
    # Use Python from virtual environment
    "$VENV_DIR/bin/python" "${OUTPUT_DIR}/tls_analyzer.py" \
        "$PCAP_FILE" \
        "${OUTPUT_DIR}/detailed_analysis.json"
}

display_results() {
    log "\nAnalysis Results Summary:" "$GREEN"

    if [ -f "${OUTPUT_DIR}/handshake_metadata.txt" ]; then
        log "\nHandshake Metadata (first 5 lines):" "$GREEN"
        head -n 5 "${OUTPUT_DIR}/handshake_metadata.txt"
    fi

    if [ -f "${OUTPUT_DIR}/cipher_suites.txt" ]; then
        log "\nDetected Cipher Suites:" "$GREEN"
        cat "${OUTPUT_DIR}/cipher_suites.txt"
    fi

    if [ -f "${OUTPUT_DIR}/detailed_analysis.json" ]; then
        log "\nDetailed Analysis Summary:" "$GREEN"
        "$VENV_DIR/bin/python" -c "
import json
with open('${OUTPUT_DIR}/detailed_analysis.json') as f:
    data = json.load(f)
print(f'Client Hello Messages: {len(data[\"client_hello\"])}')
print(f'Server Hello Messages: {len(data[\"server_hello\"])}')
"
    fi
}

cleanup() {
    sudo chmod -R 644 "${OUTPUT_DIR}"/*
    sudo chmod 755 "${OUTPUT_DIR}"
    sudo chmod -R 755 "$VENV_DIR"
}

main() {
    log "Starting TLS traffic analysis..." "$GREEN"

    install_system_dependencies
    setup_virtual_environment
    capture_traffic
    analyze_handshake
    create_python_analyzer
    run_python_analyzer
    display_results
    cleanup

    log "\nAnalysis completed. Results are in $OUTPUT_DIR" "$GREEN"
    log "Key files:" "$GREEN"
    log "- Handshake metadata: ${OUTPUT_DIR}/handshake_metadata.txt" "$GREEN"
    log "- Cipher suites: ${OUTPUT_DIR}/cipher_suites.txt" "$GREEN"
    log "- Detailed analysis: ${OUTPUT_DIR}/detailed_analysis.json" "$GREEN"
    log "- Raw capture: $PCAP_FILE" "$GREEN"

    # Deactivate virtual environment
    deactivate 2>/dev/null || true
}

main "$@"
