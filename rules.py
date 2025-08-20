def check_tls_anomalies(version, cipher_suite, sni, vuln_data):
    alerts = []

    # Detect weak TLS versions
    if version in vuln_data.get('weak_tls_versions', []):
        alerts.append(f"Weak TLS version detected: {version}")

    # Detect weak cipher suites
    if cipher_suite in vuln_data.get('weak_cipher_suites', []):
        alerts.append(f"Weak cipher suite detected: {cipher_suite}")

    # Detect known malicious domains in SNI
    if sni in vuln_data.get('known_bad_snis', []):
        alerts.append(f"SNI matches known bad domain: {sni}")

    return alerts
