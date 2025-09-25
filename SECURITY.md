# ⚠️ SECURITY WARNING

## CRITICAL SAFETY INFORMATION

### 🔴 NEVER Run in Production
This repository contains **INTENTIONALLY VULNERABLE** applications and **DESTRUCTIVE** testing tools.

### Vulnerable Applications Safety
**All vulnerable apps MUST be run with these precautions:**

1. **Network Isolation**
   - ONLY bind to `127.0.0.1` (localhost)
   - NEVER expose to `0.0.0.0` or public IPs
   - Run in isolated VLAN or VM with snapshots

2. **Docker Safety**
   ```bash
   # SAFE - Localhost only
   docker run -p 127.0.0.1:5000:5000 vulnerable-app
   
   # DANGEROUS - Never do this
   docker run -p 0.0.0.0:5000:5000 vulnerable-app
   ```

### Atomic Red Team Safety
**NEVER run atomic tests without:**
1. Taking VM snapshots first
2. Running in isolated environment
3. Using `-ShowDetails` flag first to review
4. Understanding the impact

```powershell
# SAFE - Review first
Invoke-AtomicTest T1003 -ShowDetails

# DANGEROUS - Only after review and in isolated lab
Invoke-AtomicTest T1003
```

### Secrets Management
- NEVER commit real IPs, passwords, or API keys
- Use `.example` files for templates
- Check `.gitignore` before every commit

### Responsible Disclosure
Found a real vulnerability? Contact: security@example.com

## Lab Environment Requirements
- Isolated network segment
- VM snapshots before testing
- No production data
- Regular security audits

## Legal Notice
This repository is for educational purposes only. Users are responsible for complying with all applicable laws and regulations.
