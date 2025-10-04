#!/usr/bin/env python3
import os, sys
from pathlib import Path

TEST_DATA_DIR = Path(__file__).parent / "test_data"
YARA_DIR = Path(__file__).parent.parent / "yara"

def load_rules_py(yara_dir):
    try:
        import yara
    except Exception as e:
        print("[!] yara-python not installed:", e)
        return None
    rule_files = [str(p) for p in yara_dir.glob("*.yar")]
    if not rule_files:
        print("[!] No YARA rule files found in", yara_dir)
        return None
    rules = yara.compile(filepaths={os.path.basename(f): f for f in rule_files})
    return rules

def run_tests():
    rules = load_rules_py(YARA_DIR)
    if rules is None:
        print("[!] Unable to run tests (yara-python not available). Install with: pip install yara-python")
        sys.exit(2)

    for sample in TEST_DATA_DIR.glob("*"):
        print(f"[*] Scanning sample: {sample.name}")
        matches = rules.match(str(sample))
        if matches:
            print(f"  [+] Matches: {[m.rule for m in matches]}")
        else:
            print("  [-] No match")

    print("[+] YARA tests completed")
    return 0

if __name__ == "__main__":
    run_tests()
