# 🔐 Web Security Compliance Checker

**Automated, passive web security compliance assessment — built for professionals.**

A comprehensive **Python-based security assessment tool** that evaluates web applications against **28 critical security controls**, aligned with industry best practices. Designed for **ethical, non-intrusive analysis**, it helps teams quickly identify misconfigurations and compliance gaps without exploiting vulnerabilities.

---

## 🚀 Overview

The **Web Security Compliance Checker** performs **passive security analysis** on web applications to verify adherence to modern security standards. It inspects:

* HTTPS and protocol enforcement
* HTTP security headers
* TLS/SSL configuration and known weaknesses
* HTTP method exposure
* Port accessibility
* DNS security controls

All checks are performed **safely and responsibly**, making the tool suitable for enterprise environments, audits, and pre-production reviews.

---

## ✨ Key Features

### 🛡️ 28 Comprehensive Security Checks

Covering all major web security domains:

* **Port Security**
* **HTTP / HTTPS Configuration**
* **Security Headers** (HSTS, CSP, X-Frame-Options, etc.)
* **Cookie Security Attributes**
* **HTTP Method Restrictions**
* **TLS / SSL Configuration**
* **Known Vulnerability Protections**
* **DNS CAA Record Validation**

### 📊 User-Friendly Experience

* Built with **Streamlit**
* Real-time progress tracking
* Clear compliance status with remarks
* Exportable **CSV reports**

### ⚙️ Production-Ready Architecture

* Modular, extensible design
* Robust error handling
* Graceful degradation when checks are blocked
* No dummy logic — **every check performs real analysis**

---

## 🧩 Security Checks Breakdown

### 🔌 Port Security (Check 1)

* Scans common service ports:

  ```
  21, 22, 23, 25, 80, 443, 3306, etc.
  ```
* Confirms that **only HTTP (80)** and **HTTPS (443)** are accessible
* Uses direct socket connections

---

### 🌐 HTTPS Configuration (Checks 2–3)

* Verifies site availability over HTTP and HTTPS
* Confirms **automatic HTTP → HTTPS redirection**
* Ensures HTTPS is fully operational

---

### 🕵️ Server Information Disclosure (Checks 4–6)

* Analyzes:

  * `Server` header
  * `X-Powered-By` and similar headers
  * `ETag` format for inode leakage
* Flags unnecessary version disclosure

---

### 🧱 Security Headers (Checks 7–13)

Evaluates presence and correctness of:

* `X-XSS-Protection`
* `X-Frame-Options`
* `Strict-Transport-Security`
* `Content-Security-Policy`
* Cookie flags:

  * `HttpOnly`
  * `Secure`
  * `SameSite`
* `Cache-Control`

---

### 🔄 HTTP Method Security (Checks 14–15)

* Tests for unsafe methods:

  ```
  PUT, DELETE, TRACE, OPTIONS
  ```
* Detects publicly accessible admin paths
* Verifies correct restriction responses (405 / 501)

---

### 🔐 TLS / SSL Security (Checks 16–26)

**Protocol Support Testing**

* SSLv2 ❌
* SSLv3 ❌
* TLS 1.0 ❌
* TLS 1.1 ❌
* TLS 1.2+ ✅

**Cipher Suite Analysis**

* Detects weak or deprecated ciphers

**Vulnerability Inference**

* POODLE
* Logjam
* Heartbleed
* CRIME
* CCS Injection
* FREAK
* DROWN

**Forward Secrecy**

* Confirms ECDHE / DHE support

> ⚠️ Vulnerabilities are inferred through protocol and cipher behavior — no exploitation is performed.

---

### 🌍 Protocol Version Enforcement (Check 27)

* Sends HTTP/1.0 requests
* Verifies modern protocol handling

---

### 🧾 DNS Security (Check 28)

* Queries **CAA records**
* Validates certificate issuance restrictions

---

## 🖥️ User Interface

* Clean Streamlit-based dashboard
* Real-time status updates
* Clear compliance verdicts
* Downloadable CSV security report

---

## 📁 Project Structure

```
web_security_compliance/
│
├── app.py                 # Streamlit UI
├── controller.py          # Scan orchestration
├── checks/
│   ├── https_checks.py    # HTTPS & redirect checks
│   ├── header_checks.py   # Security header analysis
│   ├── method_checks.py   # HTTP method validation
│   ├── port_checks.py     # Port accessibility tests
│   ├── tls_checks.py      # TLS/SSL inspection
│   └── dns_checks.py      # DNS security checks
│
├── results.py             # Results handling
├── utils.py               # Shared utilities
├── requirements.txt       # Dependencies
└── README.md              # Documentation
```

---

## 🛠️ Installation

### Prerequisites

* Python **3.8+**
* pip

### Setup

1. Clone or download the repository
2. Install dependencies:

```bash
pip install -r requirements.txt
```

---

## ▶️ Usage

```bash
streamlit run app.py
```

1. Open the displayed URL (usually `http://localhost:8501`)
2. Enter a target website (e.g. `https://example.com`)
3. Click **Scan Website**
4. Review findings and export the report if needed

---

## ⚖️ Ethical Considerations

This tool is **strictly passive**:

* ❌ No exploitation
* ❌ No brute force
* ❌ No DoS testing
* ❌ No vulnerability abuse
* ✅ Limited port scanning
* ✅ Respectful request rates

Designed for **audits, compliance checks, and defensive security reviews**.

---

## ⚠️ Limitations

* **TLS Vulnerabilities** are inferred, not exploited
* Firewalls and WAFs may block checks
* Python SSL libraries may not support legacy protocols
* DNS results may be cached
* Aggressive rate limiting can cause false results

---

## ✅ Security Best Practices Checklist

To achieve full compliance:

* Enforce HTTPS with redirects
* Expose only ports 80 & 443
* Remove server version disclosures
* Implement all recommended security headers
* Secure cookies properly
* Restrict HTTP methods
* Protect admin interfaces
* Use TLS 1.2+ with strong ciphers
* Enable Forward Secrecy
* Configure DNS CAA records

---

## 🧪 Troubleshooting

### “Cannot fetch headers”

* Verify URL correctness
* Check for bot blocking
* Confirm outbound HTTPS access

### “Port scan failed”

* Firewall restrictions
* Network timeout
* Rate limiting

### “TLS check failed”

* Certificate misconfiguration
* Outdated Python SSL
* Unsupported TLS setup

---

## ⚠️ Legal Notice

**IMPORTANT:** Use this tool only on:

* Systems you own
* Systems you have explicit permission to test
* Public services under responsible disclosure

Unauthorized scanning may be illegal.

---

## 🤝 Contributing

Contributions are welcome from security professionals:

* New checks
* Accuracy improvements
* Performance optimizations
* UI enhancements

---

## 📄 License

Provided for **educational and professional security assessment purposes only**. Users are responsible for legal compliance.

---

## 📌 Project Info

* **Version:** 1.0.0
* **Last Updated:** January 2026
* **Author:** Security Engineering Team

---

### ✅ Complete Implementation Highlights

✔ All 28 checks fully implemented
✔ No placeholders or mock logic
✔ Real TLS, DNS, HTTP, and socket analysis
✔ Modular, maintainable architecture
✔ Enterprise-ready documentation
✔ Immediate usability after install

---

