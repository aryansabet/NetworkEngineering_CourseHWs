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

# Just analyze TLS handshake without decryption
analyze_handshake() {
    log "Starting TLS handshake analysis..." "$GREEN"

    if [ "$CAPTURE_INTERFACE" = "eth0" ]; then
        CAPTURE_INTERFACE=$(ip route get 8.8.8.8 | awk '{print $5; exit}')
        log "Using interface: $CAPTURE_INTERFACE" "$GREEN"
    fi

    # Capture TLS traffic
    sudo tshark -i "$CAPTURE_INTERFACE" \
        -f "$CAPTURE_FILTER" \
        -w "$PCAP_FILE" \
        -a duration:"$CAPTURE_DURATION"

    # Analyze TLS handshake
    log "Extracting handshake metadata..." "$GREEN"

    # Extract basic handshake info
    sudo tshark -r "$PCAP_FILE" \
        -Y "tls.handshake" \
        -T fields \
        -e frame.number \
        -e frame.time \
        -e ip.src \
        -e ip.dst \
        -e tls.handshake.type \
        -e tls.handshake.version \
        >"${OUTPUT_DIR}/basic_handshake.txt"

    # Extract supported cipher suites
    sudo tshark -r "$PCAP_FILE" \
        -Y "tls.handshake.type == 1" \
        -T fields \
        -e tls.handshake.ciphersuite \
        >"${OUTPUT_DIR}/cipher_suites.txt"

    # Extract TLS extensions
    sudo tshark -r "$PCAP_FILE" \
        -Y "tls.handshake" \
        -T fields \
        -e tls.handshake.extension.type \
        >"${OUTPUT_DIR}/tls_extensions.txt"

    # Create comprehensive analysis
    {
        echo "TLS Handshake Analysis"
        echo "======================"
        echo
        echo "Basic Handshake Information:"
        echo "---------------------------"
        cat "${OUTPUT_DIR}/basic_handshake.txt"
        echo
        echo "Cipher Suites Offered:"
        echo "--------------------"
        cat "${OUTPUT_DIR}/cipher_suites.txt"
        echo
        echo "TLS Extensions Used:"
        echo "------------------"
        cat "${OUTPUT_DIR}/tls_extensions.txt"
    } >"${OUTPUT_DIR}/tls_analysis.txt"

    # Create JSON summary
    {
        echo "{"
        echo "  \"capture_time\": \"$(date -u '+%Y-%m-%d %H:%M:%S UTC')\","
        echo "  \"interface\": \"$CAPTURE_INTERFACE\","
        echo "  \"duration\": $CAPTURE_DURATION,"
        echo "  \"handshakes\": $(grep -c "handshake" "${OUTPUT_DIR}/basic_handshake.txt"),"
        echo "  \"cipher_suites\": $(sort -u "${OUTPUT_DIR}/cipher_suites.txt" | wc -l),"
        echo "  \"extensions\": $(sort -u "${OUTPUT_DIR}/tls_extensions.txt" | wc -l)"
        echo "}"
    } >"${OUTPUT_DIR}/summary.json"
}

main() {
    if [ "$EUID" -ne 0 ]; then
        error "Please run as root (sudo)"
    fi

    log "Starting TLS traffic analysis..." "$GREEN"

    # Install tshark if not present
    if ! command -v tshark >/dev/null 2>&1; then
        log "Installing tshark..." "$GREEN"
        sudo apt-get update
        sudo apt-get install -y tshark
    fi

    analyze_handshake

    log "\nAnalysis completed. Results are in $OUTPUT_DIR" "$GREEN"
    log "\nKey findings:" "$GREEN"
    log "$(cat ${OUTPUT_DIR}/summary.json)" "$GREEN"

    # Display simplified results
    log "\nTLS Handshake Information:" "$GREEN"
    head -n 5 "${OUTPUT_DIR}/basic_handshake.txt"

    log "\nCipher Suites (first 5):" "$GREEN"
    head -n 5 "${OUTPUT_DIR}/cipher_suites.txt"
}

main "$@"
