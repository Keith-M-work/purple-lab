#!/bin/bash
# Comprehensive recon script for penetration testing

TARGET="$1"
OUTPUT_DIR="recon_$(date +%Y%m%d_%H%M%S)"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target>"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "[*] Starting reconnaissance on $TARGET"

# Nmap scans
echo "[*] Running Nmap scans..."
nmap -sV -sC -O -oA "$OUTPUT_DIR/nmap_initial" "$TARGET"
nmap -p- -T4 -oA "$OUTPUT_DIR/nmap_full" "$TARGET"
nmap --script vuln -oA "$OUTPUT_DIR/nmap_vuln" "$TARGET"

# Web enumeration if port 80/443 open
if grep -q "80/tcp\|443/tcp" "$OUTPUT_DIR/nmap_initial.nmap"; then
    echo "[*] Web service detected, running gobuster..."
    gobuster dir -u "http://$TARGET" -w /usr/share/wordlists/dirb/common.txt -o "$OUTPUT_DIR/gobuster.txt"
fi

# DNS enumeration
echo "[*] Running DNS enumeration..."
dnsrecon -d "$TARGET" -t std -j "$OUTPUT_DIR/dnsrecon.json"

echo "[+] Reconnaissance complete. Results in $OUTPUT_DIR"
