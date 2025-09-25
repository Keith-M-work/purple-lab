#!/usr/bin/env bash
set -euo pipefail

# Usage: sudo ./pi-bootstrap.sh <hostname> [sanitized-ip]
HOSTNAME="${1:-pi}"
STATIC_IP="${2:-}"

apt-get update
apt-get -y upgrade
apt-get install -y git htop vim curl wget build-essential

hostnamectl set-hostname "$HOSTNAME"

# Docker
curl -fsSL https://get.docker.com | sh
usermod -aG docker "$SUDO_USER" || true

# Python tools
apt-get install -y python3-pip
pip3 install --upgrade pip

# YARA
apt-get install -y yara

# Filebeat (documentation/example)
curl -s https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-8.x.list
apt-get update
apt-get install -y filebeat

echo "[*] Bootstrap complete on $(hostname). Edit /etc/filebeat/filebeat.yml with your SANITIZED Elastic host and credentials."
