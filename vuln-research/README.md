# Vulnerability Research

## Recent CVEs Analyzed

### CVE-2024-12345 - Example RCE in Flask Applications
- **CVSS Score**: 9.8 (Critical)
- **Attack Vector**: Network
- **Description**: Unsafe deserialization in Flask apps using pickle
- **PoC**: See `poc/flask_rce.py`
- **Mitigation**: Update to Flask 2.3.3+

### CVE-2024-23456 - Privilege Escalation in Windows
- **CVSS Score**: 7.8 (High)
- **Attack Vector**: Local
- **Description**: Token impersonation vulnerability
- **PoC**: `poc/windows_privesc.ps1`
- **Detection**: See `../detections/sigma/2-intermediate/token_manipulation.yml`

## Research Tools
- Ghidra for reverse engineering
- AFL++ for fuzzing
- Frida for dynamic analysis

## Lab Setup
All vulnerability research is conducted in isolated VMs with snapshots.
