#!/usr/bin/env python3
import time
import requests
import random

TARGET = "http://192.0.2.100:8080"  # Your lab nginx
INTERVAL = 60  # seconds
JITTER = 10    # +/- seconds

def beacon():
    """Simulates periodic callback"""
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; MSIE 10.0)",
        "X-Session": "test-beacon-001"
    }
    try:
        r = requests.get(f"{TARGET}/callback", headers=headers, timeout=5)
        print(f"Beacon sent: {r.status_code}")
    except:
        print("Beacon failed")

if __name__ == "__main__":
    print("Starting beacon simulator (Ctrl+C to stop)")
    while True:
        beacon()
        sleep_time = INTERVAL + random.randint(-JITTER, JITTER)
        time.sleep(sleep_time)
