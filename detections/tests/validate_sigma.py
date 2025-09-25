#!/usr/bin/env python3
"""
Sigma Rule Validator - Ensures rules are properly formatted
"""
import os
import sys
import yaml
from pathlib import Path

REQUIRED_FIELDS = ['title', 'id', 'status', 'description', 'detection', 'logsource']
REQUIRED_DETECTION_FIELDS = ['condition']

def validate_sigma_rule(file_path):
    """Validate a single Sigma rule file"""
    errors = []
    warnings = []
    
    try:
        with open(file_path, 'r') as f:
            rule = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return [f"YAML parse error: {e}"], []
    
    # Check required top-level fields
    for field in REQUIRED_FIELDS:
        if field not in rule:
            errors.append(f"Missing required field: {field}")
    
    # Check detection structure
    if 'detection' in rule:
        detection = rule['detection']
        if 'condition' not in detection:
            errors.append("Detection missing 'condition' field")
        
        # Check for complex conditions that may not be portable
        if 'condition' in detection:
            condition = detection['condition']
            if 'count()' in str(condition):
                warnings.append("count() aggregation may not be supported by all backends")
            if '| by ' in str(condition):
                warnings.append("Group-by operations may require specific backend support")
    
    # Check ID format
    if 'id' in rule:
        rule_id = rule['id']
        if not isinstance(rule_id, str) or len(rule_id) != 36:
            warnings.append(f"ID should be UUID format, got: {rule_id}")
    
    # Check for potentially high FP patterns
    if 'detection' in rule:
        detection_str = str(rule['detection'])
        if 'CommandLine|contains' in detection_str:
            if not rule.get('filter') and not 'not ' in str(rule['detection'].get('condition', '')):
                warnings.append("CommandLine detection without filters may cause high FPs")
    
    return errors, warnings

def main():
    """Main validation function"""
    sigma_dir = Path('detections/sigma')
    
    if not sigma_dir.exists():
        print(f"Error: {sigma_dir} directory not found")
        sys.exit(1)
    
    total_rules = 0
    failed_rules = 0
    rules_with_warnings = 0
    
    print("Validating Sigma rules...\n")
    
    for rule_file in sigma_dir.rglob('*.yml'):
        total_rules += 1
        relative_path = rule_file.relative_to(sigma_dir)
        
        errors, warnings = validate_sigma_rule(rule_file)
        
        if errors:
            failed_rules += 1
            print(f"❌ {relative_path}")
            for error in errors:
                print(f"   ERROR: {error}")
        elif warnings:
            rules_with_warnings += 1
            print(f"⚠️  {relative_path}")
            for warning in warnings:
                print(f"   WARN: {warning}")
        else:
            print(f"✅ {relative_path}")
    
    print(f"\n{'='*50}")
    print(f"Validation Summary:")
    print(f"  Total rules: {total_rules}")
    print(f"  Passed: {total_rules - failed_rules}")
    print(f"  Failed: {failed_rules}")
    print(f"  Warnings: {rules_with_warnings}")
    
    if failed_rules > 0:
        sys.exit(1)
    else:
        print("\n✅ All rules validated successfully!")
        sys.exit(0)

if __name__ == "__main__":
    main()
