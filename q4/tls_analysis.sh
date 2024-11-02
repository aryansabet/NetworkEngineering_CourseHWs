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
LETSENCRYPT_DIR="/etc/letsencrypt/live"
TEMP_RSA_KEY="${OUTPUT_DIR}/temp_rsa.pem"
TEMP_RSA_CERT="${OUTPUT_DIR}/temp_rsa_cert.pem"

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

# Find domain from nginx configuration
find_domain() {
    local domain=""
    for conf in /etc/nginx/sites-enabled/*; do
        if [ -f "$conf" ]; then
            domain=$(grep -m 1 "server_name" "$conf" | awk '{print $2}' | tr -d ';')
            if [ ! -z "$domain" ]; then
                echo "$domain"
                return 0
            fi
        fi
    done
    return 1
}

# Convert ECDSA to RSA key for tshark
convert_to_rsa() {
    local original_key="$1"
    local original_cert="$2"

    log "Converting ECDSA key to RSA format..." "$GREEN"

    # Generate new RSA key
    openssl genrsa -out "$TEMP_RSA_KEY" 2048

    # Create CSR from original cert
    openssl req -new -key "$TEMP_RSA_KEY" -out "${OUTPUT_DIR}/temp.csr" \
        -subj "/CN=$(openssl x509 -noout -subject -in "$original_cert" | sed -n 's/.*CN=\([^/]*\).*/\1/p')"

    # Create self-signed certificate
    openssl x509 -req -days 1 \
        -in "${OUTPUT_DIR}/temp.csr" \
        -signkey "$TEMP_RSA_KEY" \
        -out "$TEMP_RSA_CERT"

    # Clean up
    rm -f "${OUTPUT_DIR}/temp.csr"

    # Set permissions
    chmod 644 "$TEMP_RSA_KEY"
    chmod 644 "$TEMP_RSA_CERT"
}

# Setup certificates
setup_certificates() {
    log "Setting up SSL certificates for analysis..." "$GREEN"

    # Find the domain
    DOMAIN=$(find_domain)
    if [ -z "$DOMAIN" ]; then
        error "Could not find domain in nginx configuration"
    fi
    log "Found domain: $DOMAIN" "$GREEN"

    # Check Let's Encrypt certificates
    SSL_KEY_PATH="${LETSENCRYPT_DIR}/${DOMAIN}/privkey.pem"
    SSL_CERT_PATH="${LETSENCRYPT_DIR}/${DOMAIN}/fullchain.pem"

    if [ ! -f "$SSL_KEY_PATH" ] || [ ! -f "$SSL_CERT_PATH" ]; then
        error "SSL certificates not found for domain $DOMAIN"
    fi

    # Convert ECDSA to RSA if necessary
    local key_type
    key_type=$(openssl pkey -in "$SSL_KEY_PATH" -text 2>/dev/null | grep -o "KEY.*" | head -1)

    if [[ $key_type == *"EC"* ]]; then
        log "Detected ECDSA key, converting to RSA..." "$GREEN"
        convert_to_rsa "$SSL_KEY_PATH" "$SSL_CERT_PATH"
        SSL_KEY_PATH="$TEMP_RSA_KEY"
        SSL_CERT_PATH="$TEMP_RSA_CERT"
    else
        log "Using existing RSA key..." "$GREEN"
        cp "$SSL_KEY_PATH" "${OUTPUT_DIR}/key.pem"
        cp "$SSL_CERT_PATH" "${OUTPUT_DIR}/cert.pem"
        SSL_KEY_PATH="${OUTPUT_DIR}/key.pem"
        SSL_CERT_PATH="${OUTPUT_DIR}/cert.pem"
    fi
}

# Install dependencies
install_dependencies() {
    log "Installing dependencies..." "$GREEN"
    sudo apt-get update
    sudo apt-get install -y \
        tshark \
        python3-full \
        python3-venv \
        openssl \
        wireshark-common

    # Setup Python virtual environment
    python3 -m venv "$OUTPUT_DIR/venv"
    source "$OUTPUT_DIR/venv/bin/activate"
    pip install scapy cryptography pyOpenSSL
}

# Capture traffic
capture_traffic() {
    log "Starting packet capture for $CAPTURE_DURATION seconds..." "$GREEN"

    if [ "$CAPTURE_INTERFACE" = "eth0" ]; then
        CAPTURE_INTERFACE=$(ip route get 8.8.8.8 | awk '{print $5; exit}')
        log "Using interface: $CAPTURE_INTERFACE" "$GREEN"
    fi

    # Capture traffic
    sudo tshark -i "$CAPTURE_INTERFACE" \
        -f "$CAPTURE_FILTER" \
        -w "$PCAP_FILE" \
        -a duration:"$CAPTURE_DURATION"
}

# Analyze traffic with RSA key
analyze_traffic() {
    log "Analyzing TLS traffic with RSA key..." "$GREEN"

    # Analyze TLS handshake metadata
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

    # Analyze cipher suites
    sudo tshark -r "$PCAP_FILE" \
        -Y "tls.handshake.type == 1" \
        -T fields \
        -e tls.handshake.ciphersuite \
        >"${OUTPUT_DIR}/cipher_suites.txt"

    # Try to decrypt with RSA key
    sudo tshark -r "$PCAP_FILE" \
        -o "tls.keys_list:${DOMAIN},443,http,${SSL_KEY_PATH}" \
        -q -z "follow,tls,ascii,0" \
        >"${OUTPUT_DIR}/decrypted_content.txt"

    # Save decrypted summary
    sudo tshark -r "$PCAP_FILE" \
        -o "tls.keys_list:${DOMAIN},443,http,${SSL_KEY_PATH}" \
        -T fields \
        -e frame.time \
        -e tls.record.content_type \
        -e tls.handshake.type \
        -E header=y \
        >"${OUTPUT_DIR}/tls_summary.txt"
}

# Create summary
create_summary() {
    log "\nAnalysis Results:" "$GREEN"

    if [ -f "${OUTPUT_DIR}/handshake_metadata.txt" ]; then
        log "\nTLS Handshake Information:" "$GREEN"
        cat "${OUTPUT_DIR}/handshake_metadata.txt"
    fi

    if [ -f "${OUTPUT_DIR}/cipher_suites.txt" ]; then
        log "\nDetected Cipher Suites:" "$GREEN"
        cat "${OUTPUT_DIR}/cipher_suites.txt"
    fi

    if [ -f "${OUTPUT_DIR}/tls_summary.txt" ]; then
        log "\nTLS Session Summary:" "$GREEN"
        cat "${OUTPUT_DIR}/tls_summary.txt"
    fi
}

# Cleanup temporary files
cleanup() {
    log "Cleaning up..." "$GREEN"
    rm -f "$TEMP_RSA_KEY" "$TEMP_RSA_CERT"
    sudo chmod -R 755 "$OUTPUT_DIR"
}

main() {
    if [ "$EUID" -ne 0 ]; then
        error "Please run as root (sudo)"
    fi

    log "Starting TLS traffic analysis..." "$GREEN"

    install_dependencies
    setup_certificates
    capture_traffic
    analyze_traffic
    create_summary
    cleanup

    log "\nAnalysis completed. Results are in $OUTPUT_DIR" "$GREEN"
    log "Key files:" "$GREEN"
    log "- Raw capture: $PCAP_FILE" "$GREEN"
    log "- Handshake metadata: ${OUTPUT_DIR}/handshake_metadata.txt" "$GREEN"
    log "- Cipher suites: ${OUTPUT_DIR}/cipher_suites.txt" "$GREEN"
    log "- TLS summary: ${OUTPUT_DIR}/tls_summary.txt" "$GREEN"
    log "- Decrypted content: ${OUTPUT_DIR}/decrypted_content.txt" "$GREEN"
}

main "$@"
