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
PROJECT_DIR="/var/www/secure-website"
LETSENCRYPT_DIR="/etc/letsencrypt/live"

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

# Check SSL certificates
setup_certificates() {
    log "Setting up SSL certificates for analysis..." "$GREEN"

    # Find the domain from nginx config
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

    # Create working copies of the certificates
    sudo cp "$SSL_KEY_PATH" "${OUTPUT_DIR}/privkey.pem"
    sudo cp "$SSL_CERT_PATH" "${OUTPUT_DIR}/fullchain.pem"
    sudo chmod 644 "${OUTPUT_DIR}/privkey.pem"
    sudo chmod 644 "${OUTPUT_DIR}/fullchain.pem"

    # Set up SSLKEYLOG for additional decryption capability
    export SSLKEYLOGFILE="${OUTPUT_DIR}/sslkey.log"
    sudo touch "$SSLKEYLOGFILE"
    sudo chmod 666 "$SSLKEYLOGFILE"
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

    # Capture with both keylog and certificate-based decryption
    sudo tshark -i "$CAPTURE_INTERFACE" \
        -f "$CAPTURE_FILTER" \
        -w "$PCAP_FILE" \
        -o "tls.keylog_file:${SSLKEYLOGFILE}" \
        -o "tls.keys_list:${DOMAIN},443,http,${OUTPUT_DIR}/privkey.pem" \
        -a duration:"$CAPTURE_DURATION"
}

# Analyze captured traffic
analyze_traffic() {
    log "Analyzing TLS traffic..." "$GREEN"

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
        -e tls.handshake.extensions.supported_version \
        -E header=y \
        >"${OUTPUT_DIR}/handshake_metadata.txt"

    # Analyze cipher suites
    sudo tshark -r "$PCAP_FILE" \
        -Y "tls.handshake.type == 1" \
        -T fields \
        -e tls.handshake.ciphersuite \
        -e tls.handshake.extensions.supported_groups \
        >"${OUTPUT_DIR}/cipher_suites.txt"

    # Try to decrypt and analyze HTTP traffic
    sudo tshark -r "$PCAP_FILE" \
        -o "tls.keylog_file:${SSLKEYLOGFILE}" \
        -o "tls.keys_list:${DOMAIN},443,http,${OUTPUT_DIR}/privkey.pem" \
        -Y "http" \
        -T fields \
        -e frame.time \
        -e http.request.method \
        -e http.request.uri \
        -e http.response.code \
        -e http.content_type \
        >"${OUTPUT_DIR}/decrypted_http.txt"

    # Save full decrypted traffic
    sudo tshark -r "$PCAP_FILE" \
        -o "tls.keylog_file:${SSLKEYLOGFILE}" \
        -o "tls.keys_list:${DOMAIN},443,http,${OUTPUT_DIR}/privkey.pem" \
        -w "$DECRYPTED_FILE"

    # Extract TLS session info
    sudo tshark -r "$PCAP_FILE" \
        -Y "tls.handshake" \
        -T json \
        >"${OUTPUT_DIR}/tls_sessions.json"
}

# Create summary report
create_summary() {
    local summary_file="${OUTPUT_DIR}/analysis_summary.txt"

    {
        echo "TLS Traffic Analysis Summary"
        echo "============================"
        echo
        echo "Domain: $DOMAIN"
        echo "Capture Duration: $CAPTURE_DURATION seconds"
        echo "Interface: $CAPTURE_INTERFACE"
        echo
        echo "TLS Handshakes:"
        grep -c "handshake" "${OUTPUT_DIR}/handshake_metadata.txt" || echo "0"
        echo
        echo "Cipher Suites Used:"
        sort -u "${OUTPUT_DIR}/cipher_suites.txt" | while read -r cipher; do
            echo "- $cipher"
        done
        echo
        echo "HTTP Requests (Decrypted):"
        wc -l <"${OUTPUT_DIR}/decrypted_http.txt"
    } >"$summary_file"

    log "\nAnalysis Summary:" "$GREEN"
    cat "$summary_file"
}

# Clean up temporary files
cleanup() {
    log "Cleaning up temporary files..." "$GREEN"
    sudo rm -f "${OUTPUT_DIR}/privkey.pem" "${OUTPUT_DIR}/fullchain.pem"
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
    log "- Decrypted capture: $DECRYPTED_FILE" "$GREEN"
    log "- Handshake metadata: ${OUTPUT_DIR}/handshake_metadata.txt" "$GREEN"
    log "- Cipher suites: ${OUTPUT_DIR}/cipher_suites.txt" "$GREEN"
    log "- Decrypted HTTP traffic: ${OUTPUT_DIR}/decrypted_http.txt" "$GREEN"
    log "- TLS sessions: ${OUTPUT_DIR}/tls_sessions.json" "$GREEN"
    log "- Analysis summary: ${OUTPUT_DIR}/analysis_summary.txt" "$GREEN"
}

main "$@"
