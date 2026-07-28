#!/usr/bin/env python3
"""
Simple Sigma top-level field validator.
Run from: detections/tests/
Exits 1 if any rule is missing required fields.

Understands both rule shapes:
  - standard detection rules: require title, id, description, detection, logsource
  - correlation rules (new Sigma format): a document with a `correlation` block
    requires title, id, description, correlation (no detection/logsource)
Handles multi-document YAML files (--- separated) so a rule and its
correlations can share a file.
"""
import sys, yaml
from pathlib import Path

REQ_DETECTION = ["title", "id", "description", "detection", "logsource"]
REQ_CORRELATION = ["title", "id", "description", "correlation"]

base = Path(__file__).parent / ".." / "sigma"
base = base.resolve()

errors = {}
for p in sorted(base.rglob("*.yml")):
    try:
        with open(p, "r", encoding="utf-8") as f:
            docs = list(yaml.safe_load_all(f))
    except Exception as e:
        errors[p.name] = [f"YAML parse error: {e}"]
        continue

    docs = [d for d in docs if d]  # skip empty documents
    if not docs:
        errors[p.name] = ["empty file - no YAML documents"]
        continue

    file_errors = []
    for i, r in enumerate(docs):
        label = f"doc {i+1}" if len(docs) > 1 else "rule"
        req = REQ_CORRELATION if "correlation" in r else REQ_DETECTION
        missing = [k for k in req if k not in r]
        if missing:
            file_errors.append(f"{label} ({r.get('title', '?')}): missing {missing}")
    if file_errors:
        errors[p.name] = file_errors

if errors:
    print("Validation FAILED:")
    for k, v in errors.items():
        for item in v:
            print(f" - {k}: {item}")
    sys.exit(1)
print("All Sigma rules contain required top-level fields.")
sys.exit(0)
