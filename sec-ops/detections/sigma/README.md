# Sigma Detection Rules

## Overview
This directory contains Sigma rules organized by complexity level, demonstrating progression in detection engineering skills.

## Structure
- `1-beginner/` - Basic single-event detections
- `2-intermediate/` - Multi-condition rules with filters
- `3-advanced/` - Behavioral correlation and chains
- `4-expert/` - Complex APT detection patterns

## Usage

### Convert to Elastic
```bash
sigmac -t es-query powershell_download.yml -o elastic_rule.json
```

### Convert to Splunk
```bash
sigmac -t splunk lsass_access.yml -o splunk_rule.txt
```

## Testing
Run the validation script:
```python
python ../tests/validate_sigma.py
```

## Coverage
- 15+ MITRE ATT&CK techniques
- Windows, Linux, and cloud detections
- Validated against real attack data
