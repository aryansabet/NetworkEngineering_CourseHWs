from scapy.all import *
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import json

def extract_certificate_info(cert_bytes):
    """Extract information from a X.509 certificate."""
    try:
        cert = x509.load_der_x509_certificate(cert_bytes)
        return {
            'subject': str(cert.subject),
            'issuer': str(cert.issuer),
            'not_before': cert.not_valid_before.isoformat(),
            'not_after': cert.not_valid_after.isoformat(),
            'serial_number': hex(cert.serial_number)
        }
    except Exception as e:
        return {'error': str(e)}

def analyze_tls_session(pcap_file, output_file):
    """Analyze a TLS session from a PCAP file."""
    packets = rdpcap(pcap_file)
    
    analysis = {
        'handshake_sequence': [],
        'certificates': [],
        'cipher_suites': set(),
        'extensions': set()
    }
    
    for packet in packets:
        if TLS in packet:
            # Record handshake sequence
            if packet.haslayer(TLSHandshake):
                handshake = {
                    'type': packet[TLSHandshake].type,
                    'length': packet[TLSHandshake].length,
                    'time': float(packet.time)
                }
                analysis['handshake_sequence'].append(handshake)
            
            # Extract certificates
            if packet.haslayer(TLSCertificate):
                cert_data = extract_certificate_info(packet[TLSCertificate].data)
                analysis['certificates'].append(cert_data)
            
            # Record cipher suites
            if packet.haslayer(TLSClientHello):
                for cipher in packet[TLSClientHello].ciphers:
                    analysis['cipher_suites'].add(cipher.name)
            
            # Record extensions
            if packet.haslayer(TLSExtension):
                analysis['extensions'].add(packet[TLSExtension].type.name)
    
    # Convert sets to lists for JSON serialization
    analysis['cipher_suites'] = list(analysis['cipher_suites'])
    analysis['extensions'] = list(analysis['extensions'])
    
    # Write analysis to file
    with open(output_file, 'w') as f:
        json.dump(analysis, f, indent=2)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python3 tls_analyzer.py <pcap_file> <output_file>")
        sys.exit(1)
    
    analyze_tls_session(sys.argv[1], sys.argv[2])