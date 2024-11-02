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

# Convert ECDSA key to RSA for tshark compatibility
convert_key() {
    local key_type
    key_type=$(openssl pkey -in "$SSL_KEY_PATH" -text | grep -o "PRIVATE KEY.*" | head -1)

    if [[ $key_type == *"EC PRIVATE KEY"* ]]; then
        log "Converting ECDSA key to RSA format..." "$GREEN"

        # Generate temporary RSA key
        openssl genrsa -out "${OUTPUT_DIR}/temp_rsa.pem" 2048

        # Generate CSR using the original cert
        openssl x509 -in "$SSL_CERT_PATH" -x509toreq -signkey "$SSL_KEY_PATH" -out "${OUTPUT_DIR}/temp.csr"

        # Sign with the new RSA key
        openssl x509 -req -days 1 -in "${OUTPUT_DIR}/temp.csr" -signkey "${OUTPUT_DIR}/temp_rsa.pem" -out "${OUTPUT_DIR}/temp_cert.pem"

        # Use the new RSA key for decryption
        SSL_KEY_PATH="${OUTPUT_DIR}/temp_rsa.pem"
        SSL_CERT_PATH="${OUTPUT_DIR}/temp_cert.pem"

        # Cleanup CSR
        rm -f "${OUTPUT_DIR}/temp.csr"
    else
        log "Using existing RSA key..." "$GREEN"
        cp "$SSL_KEY_PATH" "${OUTPUT_DIR}/privkey.pem"
        cp "$SSL_CERT_PATH" "${OUTPUT_DIR}/cert.pem"
        SSL_KEY_PATH="${OUTPUT_DIR}/privkey.pem"
        SSL_CERT_PATH="${OUTPUT_DIR}/cert.pem"
    fi

    # Set permissions
    chmod 644 "$SSL_KEY_PATH"
    chmod 644 "$SSL_CERT_PATH"
}

# Check SSL certificates
check_certificates() {
    log "Checking SSL certificates..." "$GREEN"
    if [ ! -f "$SSL_KEY_PATH" ] || [ ! -f "$SSL_CERT_PATH" ]; then
        error "SSL certificates not found. Please ensure Let's Encrypt certificates are properly installed."
    fi
    convert_key
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

    python3 -m venv "$OUTPUT_DIR/venv"
    source "$OUTPUT_DIR/venv/bin/activate"
    pip install scapy cryptography pyOpenSSL
}

# Export SSLKEYLOG for Chrome/Firefox
setup_sslkeylog() {
    export SSLKEYLOGFILE="${OUTPUT_DIR}/sslkey.log"
    touch "$SSLKEYLOGFILE"
    chmod 666 "$SSLKEYLOGFILE"
    log "SSLKEYLOG file setup at $SSLKEYLOGFILE" "$GREEN"
}

# Capture traffic with both key methods
capture_traffic() {
    log "Starting packet capture for $CAPTURE_DURATION seconds..." "$GREEN"

    if [ "$CAPTURE_INTERFACE" = "eth0" ]; then
        CAPTURE_INTERFACE=$(ip route get 8.8.8.8 | awk '{print $5; exit}')
        log "Using interface: $CAPTURE_INTERFACE" "$GREEN"
    fi

    # Capture with both SSLKEYLOG and private key
    sudo tshark -i "$CAPTURE_INTERFACE" \
        -f "$CAPTURE_FILTER" \
        -w "$PCAP_FILE" \
        -o "tls.keylog_file:${SSLKEYLOGFILE}" \
        -o "tls.keys_list:${DOMAIN},443,http,${SSL_KEY_PATH}" \
        -a duration:"$CAPTURE_DURATION"
}

analyze_traffic() {
    log "Analyzing TLS traffic..." "$GREEN"

    # Extract handshake metadata
    sudo tshark -r "$PCAP_FILE" \
        -Y "tls.handshake" \
        -T fields \
        -e frame.number \
        -e frame.time \
        -e ip.src \
        -e ip.dst \
        -e tls.handshake.type \
        -e tls.handshake.version \
        -e tls.handshake.extensions.supported_version \
        -E header=y \
        >"${OUTPUT_DIR}/handshake_metadata.txt"

    # Extract cipher suites and key exchange info
    sudo tshark -r "$PCAP_FILE" \
        -Y "tls.handshake.type == 1" \
        -T fields \
        -e tls.handshake.ciphersuite \
        -e tls.handshake.extensions.supported_groups \
        >"${OUTPUT_DIR}/cipher_suites.txt"

    # Try decryption with both methods
    sudo tshark -r "$PCAP_FILE" \
        -o "tls.keylog_file:${SSLKEYLOGFILE}" \
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
        -o "tls.keylog_file:${SSLKEYLOGFILE}" \
        -o "tls.keys_list:${DOMAIN},443,http,${SSL_KEY_PATH}" \
        -w "$DECRYPTED_FILE"
}

[... rest of the script remains the same ...]

main() {
    if [ "$EUID" -ne 0 ]; then
        error "Please run as root (sudo)"
    fi

    log "Starting TLS traffic analysis with decryption..." "$GREEN"

    install_dependencies
    setup_sslkeylog
    check_certificates
    capture_traffic
    analyze_traffic
    create_python_analyzer
    run_python_analyzer
    display_results

    # Cleanup temporary files
    rm -f "${OUTPUT_DIR}/temp_rsa.pem" "${OUTPUT_DIR}/temp_cert.pem"

    log "\nAnalysis completed. Results are in $OUTPUT_DIR" "$GREEN"
    log "Key files:" "$GREEN"
    log "- Raw capture: $PCAP_FILE" "$GREEN"
    log "- Decrypted capture: $DECRYPTED_FILE" "$GREEN"
    log "- Handshake metadata: ${OUTPUT_DIR}/handshake_metadata.txt" "$GREEN"
    log "- Decrypted HTTP traffic: ${OUTPUT_DIR}/decrypted_http.txt" "$GREEN"
    log "- Detailed analysis: ${OUTPUT_DIR}/detailed_analysis.json" "$GREEN"
    log "- SSL key log: $SSLKEYLOGFILE" "$GREEN"
}

main "$@"
