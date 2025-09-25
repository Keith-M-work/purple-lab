#!/usr/bin/env python3
"""
Simple Sigma top-level field validator.
Run from: detections/tests/
Exits 1 if any rule is missing required fields.
"""
import sys, yaml
from pathlib import Path

REQ = ["title", "id", "description", "detection", "logsource"]

base = Path(__file__).parent / ".." / "sigma"
base = base.resolve()

errors = {}
for p in sorted(base.rglob("*.yml")):
    try:
        with open(p, "r", encoding="utf-8") as f:
            r = yaml.safe_load(f)
    except Exception as e:
        errors[p.name] = [f"YAML parse error: {e}"]
        continue
    missing = [k for k in REQ if (not r) or (k not in r)]
    if missing:
        errors[p.name] = missing

if errors:
    print("Validation FAILED:")
    for k,v in errors.items():
        print(f" - {k}: missing {v}")
    sys.exit(1)
print("All Sigma rules contain required top-level fields.")
sys.exit(0)
