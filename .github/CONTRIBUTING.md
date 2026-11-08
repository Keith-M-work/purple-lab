# Contributing to Purple Lab

## Security First
Before contributing, review [SECURITY.md](SECURITY.md) for critical safety information.

## Contribution Guidelines

### Detection Rules
1. Test all rules against real telemetry
2. Include false positive documentation
3. Map to MITRE ATT&CK
4. Run validation: `python detections/tests/validate_sigma.py`

### Vulnerable Applications
1. Default to localhost binding (127.0.0.1)
2. Include clear security warnings
3. Provide safe shutdown procedures
4. Never include real exploits that could harm

### Pull Request Process
1. Create feature branch: `git checkout -b feature/your-feature`
2. Test thoroughly in isolated environment
3. Update documentation
4. Ensure CI passes
5. Submit PR with clear description

### Code of Conduct
- Never commit secrets or real infrastructure details
- Respect security boundaries
- Test destructive operations only in isolation
- Report security issues privately

## Testing
```bash
# Validate Sigma rules
python detections/tests/validate_sigma.py

# Test YARA rules
python detections/tests/run_yara_tests.py
```

## Questions?
Open an issue for discussion before major changes.
