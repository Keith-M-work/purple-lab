#!/usr/bin/env python3
"""Enhanced Sigma Rule Validator"""
import os
import sys
import yaml
import re
from pathlib import Path

REQUIRED_FIELDS = ['title', 'id', 'status', 'description', 'detection', 'logsource']

def validate_sigma_rule(file_path):
    """Validate a Sigma rule file"""
    errors = []
    warnings = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            rule = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return [f"YAML parse error: {e}"], []
    
    # Check required fields
    for field in REQUIRED_FIELDS:
        if field not in rule:
            errors.append(f"Missing required field: {field}")
    
    # Check detection structure
    if 'detection' in rule:
        detection = rule['detection']
        if 'condition' not in detection:
            errors.append("Detection missing 'condition' field")
        else:
            condition = str(detection['condition'])
            if 'count(' in condition:
                warnings.append("count() may not be supported by all backends")
            if '| by ' in condition:
                warnings.append("'by' grouping may not be supported by all backends")
    
    return errors, warnings

def main():
    sigma_dir = Path('detections/sigma')
    
    if not sigma_dir.exists():
        print(f"Error: {sigma_dir} directory not found")
        sys.exit(1)
    
    print("Enhanced Sigma Rule Validation\n")
    
    total = 0
    failed = 0
    
    for rule_file in sigma_dir.rglob('*.yml'):
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
