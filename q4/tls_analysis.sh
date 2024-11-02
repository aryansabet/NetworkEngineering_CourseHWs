#!/bin/bash

# Exit on error
set -e

# Configuration
CAPTURE_INTERFACE="eth0"
CAPTURE_DURATION=60
CAPTURE_FILTER="tcp port 443"
OUTPUT_DIR="/tmp/tls_analysis"
LOG_FILE="${OUTPUT_DIR}/analysis.log"
PCAP_FILE="${OUTPUT_DIR}/capture.pcap"
DECRYPTED_FILE="${OUTPUT_DIR}/decrypted.pcap"
DOMAIN="aryansabet.com"
SSL_KEY_PATH="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
SSL_CERT_PATH="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"

# Colors
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

# Check SSL certificates
check_certificates() {
    log "Checking SSL certificates..." "$GREEN"
    if [ ! -f "$SSL_KEY_PATH" ] || [ ! -f "$SSL_CERT_PATH" ]; then
        error "SSL certificates not found. Please ensure Let's Encrypt certificates are properly installed."
    fi

    # Create a copy of the private key with proper permissions for tshark
    sudo cp "$SSL_KEY_PATH" "${OUTPUT_DIR}/privkey.pem"
    sudo chmod 644 "${OUTPUT_DIR}/privkey.pem"
    SSL_KEY_PATH="${OUTPUT_DIR}/privkey.pem"
}

# Install dependencies
install_dependencies() {
    log "Installing dependencies..." "$GREEN"
    sudo apt-get update
    sudo apt-get install -y \
        tshark \
        python3-full \
        python3-venv \
        curl \
        openssl \
        wireshark-common

    # Create Python virtual environment
    python3 -m venv "$OUTPUT_DIR/venv"
    source "$OUTPUT_DIR/venv/bin/activate"
    pip install scapy cryptography
}

# Capture traffic with decryption
capture_traffic() {
    log "Starting packet capture with TLS decryption for $CAPTURE_DURATION seconds..." "$GREEN"

    if [ "$CAPTURE_INTERFACE" = "eth0" ]; then
        CAPTURE_INTERFACE=$(ip route get 8.8.8.8 | awk '{print $5; exit}')
        log "Using interface: $CAPTURE_INTERFACE" "$GREEN"
    fi

    # Capture traffic with TLS decryption
    sudo tshark -i "$CAPTURE_INTERFACE" \
        -f "$CAPTURE_FILTER" \
        -w "$PCAP_FILE" \
        -o "tls.keys_list:${DOMAIN},443,http,${SSL_KEY_PATH}" \
        -a duration:"$CAPTURE_DURATION"
}

# Analyze TLS handshake and decrypted content
analyze_traffic() {
    log "Analyzing TLS traffic..." "$GREEN"

    # Analyze handshake metadata
    sudo tshark -r "$PCAP_FILE" \
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

    # Extract cipher suites
    sudo tshark -r "$PCAP_FILE" \
        -Y "tls.handshake.type == 1" \
        -T fields \
        -e tls.handshake.ciphersuite \
        >"${OUTPUT_DIR}/cipher_suites.txt"

    # Decrypt and analyze HTTP content
    sudo tshark -r "$PCAP_FILE" \
        -o "tls.keys_list:${DOMAIN},443,http,${SSL_KEY_PATH}" \
        -Y "http" \
        -T fields \
        -e http.request.method \
        -e http.request.uri \
        -e http.response.code \
        -e http.content_type \
        >"${OUTPUT_DIR}/decrypted_http.txt"

    # Save full decrypted traffic
    sudo tshark -r "$PCAP_FILE" \
        -o "tls.keys_list:${DOMAIN},443,http,${SSL_KEY_PATH}" \
        -w "$DECRYPTED_FILE"
}

# Create Python analyzer script
create_python_analyzer() {
    cat >"${OUTPUT_DIR}/tls_analyzer.py" <<'EOF'
from scapy.all import *
from scapy.layers.tls.all import *
import sys
import json

def get_tls_version(version_int):
    versions = {
        0x0300: "SSLv3",
        0x0301: "TLSv1.0",
        0x0302: "TLSv1.1",
        0x0303: "TLSv1.2",
        0x0304: "TLSv1.3"
    }
    return versions.get(version_int, f"Unknown (0x{version_int:04x})")

def get_cipher_suite(cipher_int):
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

def analyze_decrypted_pcap(pcap_file, output_file):
    packets = rdpcap(pcap_file)
    results = {
        'handshake': {
            'client_hello': [],
            'server_hello': [],
        },
        'decrypted_content': {
            'http_requests': [],
            'http_responses': []
        }
    }

    for pkt in packets:
        try:
            if TLS in pkt:
                if TLSClientHello in pkt:
                    hello = pkt[TLSClientHello]
                    results['handshake']['client_hello'].append({
                        'timestamp': float(pkt.time),
                        'version': get_tls_version(hello.version),
                        'cipher_suites': [get_cipher_suite(c) for c in hello.ciphers] if hasattr(hello, 'ciphers') else []
                    })
                elif TLSServerHello in pkt:
                    hello = pkt[TLSServerHello]
                    results['handshake']['server_hello'].append({
                        'timestamp': float(pkt.time),
                        'version': get_tls_version(hello.version),
                        'selected_cipher': get_cipher_suite(hello.cipher) if hasattr(hello, 'cipher') else 'Unknown'
                    })

            # Analyze decrypted HTTP content if available
            if Raw in pkt and (b'HTTP/' in pkt[Raw].load or b'GET ' in pkt[Raw].load or b'POST ' in pkt[Raw].load):
                content = pkt[Raw].load.decode('utf-8', errors='ignore')
                if 'GET ' in content or 'POST ' in content:
                    results['decrypted_content']['http_requests'].append({
                        'timestamp': float(pkt.time),
                        'content': content[:200] + '...' if len(content) > 200 else content
                    })
                elif 'HTTP/' in content:
                    results['decrypted_content']['http_responses'].append({
                        'timestamp': float(pkt.time),
                        'content': content[:200] + '...' if len(content) > 200 else content
                    })

        except Exception as e:
            print(f"Error processing packet: {e}")
            continue

    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    # Print summary
    print("\nAnalysis Summary:")
    print(f"Client Hello Messages: {len(results['handshake']['client_hello'])}")
    print(f"Server Hello Messages: {len(results['handshake']['server_hello'])}")
    print(f"Decrypted HTTP Requests: {len(results['decrypted_content']['http_requests'])}")
    print(f"Decrypted HTTP Responses: {len(results['decrypted_content']['http_responses'])}")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python3 tls_analyzer.py <pcap_file> <output_file>")
        sys.exit(1)

    analyze_decrypted_pcap(sys.argv[1], sys.argv[2])
EOF

    sudo chmod +x "${OUTPUT_DIR}/tls_analyzer.py"
}

# Run the Python analyzer
run_python_analyzer() {
    log "Running detailed TLS analysis with decryption..." "$GREEN"
    source "$OUTPUT_DIR/venv/bin/activate"
    python3 "${OUTPUT_DIR}/tls_analyzer.py" \
        "$DECRYPTED_FILE" \
        "${OUTPUT_DIR}/detailed_analysis.json"
}

# Display results summary
display_results() {
    log "\nAnalysis Results:" "$GREEN"

    # Display handshake metadata
    if [ -f "${OUTPUT_DIR}/handshake_metadata.txt" ]; then
        log "\nHandshake Metadata:" "$GREEN"
        cat "${OUTPUT_DIR}/handshake_metadata.txt"
    fi

    # Display decrypted HTTP content
    if [ -f "${OUTPUT_DIR}/decrypted_http.txt" ]; then
        log "\nDecrypted HTTP Traffic:" "$GREEN"
        cat "${OUTPUT_DIR}/decrypted_http.txt"
    fi

    # Display detailed analysis
    if [ -f "${OUTPUT_DIR}/detailed_analysis.json" ]; then
        log "\nDetailed Analysis Summary:" "$GREEN"
        python3 -c "
import json
with open('${OUTPUT_DIR}/detailed_analysis.json') as f:
    data = json.load(f)
print(f'Handshake Analysis:')
print(f'- Client Hello Messages: {len(data[\"handshake\"][\"client_hello\"])}')
print(f'- Server Hello Messages: {len(data[\"handshake\"][\"server_hello\"])}')
print(f'\nDecrypted Content Analysis:')
print(f'- HTTP Requests: {len(data[\"decrypted_content\"][\"http_requests\"])}')
print(f'- HTTP Responses: {len(data[\"decrypted_content\"][\"http_responses\"])}')
"
    fi
}

# Main function
main() {
    if [ "$EUID" -ne 0 ]; then
        error "Please run as root (sudo)"
    fi

    log "Starting TLS traffic analysis with decryption..." "$GREEN"

    check_certificates
    install_dependencies
    capture_traffic
    analyze_traffic
    create_python_analyzer
    run_python_analyzer
    display_results

    log "\nAnalysis completed. Results are in $OUTPUT_DIR" "$GREEN"
    log "Key files:" "$GREEN"
    log "- Raw capture: $PCAP_FILE" "$GREEN"
    log "- Decrypted capture: $DECRYPTED_FILE" "$GREEN"
    log "- Handshake metadata: ${OUTPUT_DIR}/handshake_metadata.txt" "$GREEN"
    log "- Decrypted HTTP traffic: ${OUTPUT_DIR}/decrypted_http.txt" "$GREEN"
    log "- Detailed analysis: ${OUTPUT_DIR}/detailed_analysis.json" "$GREEN"
}

main "$@"
