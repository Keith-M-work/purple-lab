# Havoc C2 - Detection Signatures

## Observable Patterns
- Default ports: 40056 (Demon), 443 (HTTPS)
- User-Agent patterns (when not customized)
- Certificate patterns
- Beacon timing intervals

## Detection Opportunities
- TLS fingerprinting (JA3/JA3S)
- Network flow analysis
- Process creation patterns
- Named pipe indicators

## Sample Wazuh Rule
See `/detections/wazuh/c2_patterns.xml`
