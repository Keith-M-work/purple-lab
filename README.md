# 🔬 Purple Lab - Cybersecurity Detection & Testing

## 🎯 Overview
A comprehensive purple team lab for detection engineering, vulnerability research, and security testing.

## 📁 Repository Structure

### Detection Engineering
- **`detections/sigma/`** - Sigma rules from beginner to expert level
- **`detections/yara/`** - YARA rules for malware detection
- **`detections/tests/`** - Validation scripts and test data

### Vulnerable Applications
- **`vuln-apps/`** - Intentionally vulnerable applications for testing
- **`vuln-research/`** - CVE analysis and PoCs

### Reconnaissance & Testing
- **`recon/`** - Automated reconnaissance scripts
- **`atomic/`** - Atomic Red Team integration
- **`scripts/`** - Utility and bootstrap scripts

### Infrastructure
- **`inventory/`** - Hardware and network inventory
- **`examples/`** - Configuration examples
- **`docs/`** - Documentation and playbooks

## 🚀 Quick Start

### 1. Clone and Setup
```bash
git clone https://github.com/Keith-M-work/purple-lab.git
cd purple-lab
```

### 2. Test Detection Rules
```python
# Validate YARA rules
python detections/tests/run_yara_tests.py

# Validate Sigma rules
python detections/tests/validate_sigma.py
```

### 3. Run Vulnerable Apps
```bash
# Flask SQLi app
cd vuln-apps/flask-sqli
docker build -t flask-vuln .
docker run -p 127.0.0.1:5000:5000 flask-vuln
```

### 4. Execute Atomic Tests
```powershell
# Run atomic red team tests
powershell atomic/run_atomic_tests.ps1
```

## 📊 Detection Coverage

### Sigma Rules
- **Beginner**: 2 rules (PowerShell, Authentication)
- **Intermediate**: 2 rules (LSASS, Persistence)
- **Advanced**: 1 rule (Ransomware chains)
- **Expert**: 1 rule (APT detection)

### YARA Rules
- PowerShell suspicious patterns
- Mimikatz-like behavior
- Cobalt Strike beacons
- Generic ransomware

## 🛠️ Lab Environment
- **OS**: Windows 11 + Ubuntu VMs
- **SIEM**: Wazuh/Elastic Stack
- **Network**: Isolated VLANs
- **Hardware**: Raspberry Pi cluster

## 📚 Documentation
- [Detection Philosophy](docs/demo-playbook.md)
- [Lab Setup Guide](docs/setup.md)
- [Vulnerability Research](vuln-research/README.md)

## ⚠️ Security Notice
This repository contains:
- Intentionally vulnerable applications
- Offensive security tools
- Attack simulations

**Use only in isolated lab environments!**

## 📝 License
MIT License - See LICENSE file

## 👤 Author
Keith M - Security Engineer
- GitHub: [@Keith-M-work](https://github.com/Keith-M-work)

## 🤝 Contributing
Pull requests welcome for:
- New detection rules
- Vulnerability research
- Documentation improvements

## Legal and Ethical Use Only

**This repository is for educational and defensive security purposes only.**

- Use the code and examples **only** in isolated lab environments (VMs with snapshots, isolated VLANs, or disposable hardware).
- Do **not** run offensive techniques or tests against systems you do not own or do not have **explicit, written permission** to test.
- Obtain written authorization before performing security testing on third-party or production systems.
- Follow all applicable laws, regulations, and your organization�s policies.
- If you are unsure whether a test is permitted, stop and seek legal or managerial approval.

By using the content of this repository you agree to act responsibly and ethically.

