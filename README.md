# TLS-threat-detector

# 🔐 TLS Threat Detector

A real-time TLS metadata analysis and anomaly detection tool built with Python and PyShark. Designed to help SOC analysts and security engineers identify weak encryption, deprecated TLS versions, and suspicious server names (SNI) — without decrypting the traffic.

---

## 📦 Features
- ✅ Extracts critical TLS handshake metadata:
  - TLS version
  - Cipher suite
  - Server Name Indication (SNI)
- ✅ Detects:
  - Weak TLS versions (e.g. TLS 1.0 / SSLv3)
  - Weak cipher suites (e.g. NULL, EXPORT)
  - Known malicious or suspicious SNI values
- ✅ JSON-based threat intelligence for easy updates
- ✅ Modular `rules.py` detection engine
- ✅ CLI output with alert context

---

## 🧠 Why This Matters

Many networks still use outdated encryption protocols that pose serious security risks — including TLS downgrade attacks, null cipher use, and traffic tunneling. This tool brings visibility to these threats without needing to decrypt traffic.

---
