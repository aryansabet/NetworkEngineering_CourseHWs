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