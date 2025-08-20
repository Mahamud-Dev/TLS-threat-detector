import pyshark
import json
from rules import check_tls_anomalies
import os 

interface = 'eth0'
tls_packets = pyshark.LiveCapture(interface=interface, display_filter='tls')


vuln_path = os.path.join('..', 'json', 'vulnerabilities.json')
with open(vuln_path) as f:
    vuln_data = json.load(f)


print("[*] Live TLS detection started...\n")

for pkt in tls_packets:
    if hasattr(pkt, 'tls'):
        version = getattr(pkt.tls, 'record_version', 'N/A')
        handshake_type = getattr(pkt.tls, 'handshake_type', 'N/A')
        cipher_suite = getattr(pkt.tls, 'handshake_ciphersuite', 'N/A')
        sni = getattr(pkt.tls, 'handshake_extensions_server_name', 'N/A')

        alerts = check_tls_anomalies(version, cipher_suite, sni, vuln_data)

        for alert in alerts:
            print(f'[ALERT] {alert} | SNI: {sni} | Cipher: {cipher_suite} | Version: {version}')










