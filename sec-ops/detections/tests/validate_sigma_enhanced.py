#!/usr/bin/env python3
"""Enhanced Sigma Rule Validator

Validates two rule shapes:
  - standard detection rules (title, id, status, description, detection, logsource)
  - correlation rules (title, id, status, description, correlation) - the new
    Sigma correlation format, which has no detection/logsource block

Handles multi-document YAML files. Beyond structure it performs light
metadata/taxonomy checks (MITRE ATT&CK tags, level) as warnings, per the
detection-as-code practice of validating metadata and taxonomy in CI.
"""
import sys
import yaml
from pathlib import Path

REQUIRED_DETECTION = ['title', 'id', 'status', 'description', 'detection', 'logsource']
REQUIRED_CORRELATION = ['title', 'id', 'status', 'description', 'correlation']
VALID_CORRELATION_TYPES = {'event_count', 'value_count', 'temporal', 'temporal_ordered'}
VALID_LEVELS = {'informational', 'low', 'medium', 'high', 'critical'}


def validate_document(rule, label):
    """Validate a single parsed YAML document (rule)."""
    errors = []
    warnings = []

    if not isinstance(rule, dict):
        return [f"{label}: not a mapping"], []

    # A new-format correlation rule has a `correlation` block and NO `detection`.
    # Legacy hybrids that carry both keys are validated as detection rules.
    is_correlation = 'correlation' in rule and 'detection' not in rule
    required = REQUIRED_CORRELATION if is_correlation else REQUIRED_DETECTION

    for field in required:
        if field not in rule:
            errors.append(f"{label}: missing required field: {field}")

    if is_correlation:
        corr = rule['correlation'] or {}
        ctype = corr.get('type')
        if ctype not in VALID_CORRELATION_TYPES:
            errors.append(f"{label}: correlation.type '{ctype}' not one of {sorted(VALID_CORRELATION_TYPES)}")
        if 'rules' not in corr:
            errors.append(f"{label}: correlation missing 'rules' reference")
        if 'timespan' not in corr:
            errors.append(f"{label}: correlation missing 'timespan'")
        if ctype == 'value_count' and 'field' not in (corr.get('condition') or {}):
            errors.append(f"{label}: value_count correlation condition missing 'field'")
    else:
        detection = rule.get('detection', {})
        if isinstance(detection, dict) and 'condition' not in detection:
            errors.append(f"{label}: detection missing 'condition' field")

    # Metadata / taxonomy checks (warnings)
    tags = rule.get('tags') or []
    if not any(str(t).startswith('attack.') for t in tags):
        warnings.append(f"{label}: no MITRE ATT&CK (attack.*) taxonomy tag")
    level = rule.get('level')
    if level is not None and level not in VALID_LEVELS:
        warnings.append(f"{label}: level '{level}' not one of {sorted(VALID_LEVELS)}")

    return errors, warnings


def validate_sigma_rule(file_path):
    """Validate every document in a Sigma rule file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            docs = [d for d in yaml.safe_load_all(f) if d]
    except yaml.YAMLError as e:
        return [f"YAML parse error: {e}"], []

    if not docs:
        return ["empty file - no YAML documents"], []

    errors, warnings = [], []
    for i, doc in enumerate(docs):
        label = f"doc {i + 1}" if len(docs) > 1 else "rule"
        e, w = validate_document(doc, label)
        errors.extend(e)
        warnings.extend(w)
    return errors, warnings


def main():
    # Resolve the sigma directory relative to this script so the validator works
    # from any working directory.
    sigma_dir = (Path(__file__).parent / '..' / 'sigma').resolve()

    if not sigma_dir.exists():
        print(f"Error: {sigma_dir} directory not found")
        sys.exit(1)

    print("Enhanced Sigma Rule Validation\n")

    total = 0
    failed = 0

    for rule_file in sorted(sigma_dir.rglob('*.yml')):
        total += 1
        relative_path = rule_file.relative_to(sigma_dir)

        errors, warnings = validate_sigma_rule(rule_file)

        if errors:
            failed += 1
            print(f"FAIL: {relative_path}")
            for error in errors:
                print(f"  ERROR: {error}")
        elif warnings:
            print(f"WARN: {relative_path}")
            for warning in warnings:
                print(f"  WARNING: {warning}")
        else:
            print(f"PASS: {relative_path}")

    print(f"\nTotal: {total}, Failed: {failed}")

    if failed > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
