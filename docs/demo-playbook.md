# Demo Playbook â€” Step-by-step (sanitized placeholders)

This playbook shows an end-to-end demo you can run in a safe, isolated environment.  
**All example IPs are sanitized and use documentation placeholders (192.0.2.x, 198.51.100.x). Replace before applying.**

Quick goal: deploy 5 Pis (pi-1..pi-5), install agents, run demo containers (vuln server + Juice Shop), run YARA & Sigma tests, and collect proof artifacts.

## Prereqs
- pfSense / Netgate SG-2100 admin access
- VLAN-capable managed switch
- 5 Raspberry Pis (pi-1..pi-5)
- Admin workstation with git & docker
- A sanitized Elastic endpoint (example: http://198.51.100.20:9200)

## Top-level order
1. Commit inventory & playbook to repo
2. Configure VLANs in pfSense and switch
3. Create DHCP static mappings for pi-1..pi-5
4. Boot Pis, confirm IPs, and collect proof
5. Bootstrap Pis (docker, filebeat, yara)
6. Deploy vuln containers (vuln-server, juiceshop)
7. Run YARA & Sigma validations and vuln tests
8. Capture proof artifacts into examples/deploy-proof/
9. Optionally run CI to validate rules and tests

## Pi inventory (sanitized)
| Hostname | Role | VLAN ID | IP (example) |
|----------|------|---------|--------------|
| pi-1     | malware lab             | 10 | 192.0.2.10 |
| pi-2     | reverse engineering     | 20 | 192.0.2.11 |
| pi-3     | honeypot                | 30 | 192.0.2.12 |
| pi-4     | security infra (agents) | 40 | 192.0.2.13 |
| pi-5     | containers / k3s        | 50 | 192.0.2.14 |

## Key commands & verification (paste outputs into examples/deploy-proof/)
- Ping/ssh verify:
  `ssh pi@192.0.2.10 'hostname && ip -4 addr show eth0' > examples/deploy-proof/pi-1-addr.txt`
- Docker check:
  `ssh pi@192.0.2.14 'docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}"' > examples/deploy-proof/pi-5-docker-ps.txt`
- Filebeat status:
  `ssh pi@192.0.2.13 'sudo systemctl status filebeat --no-pager' > examples/deploy-proof/pi-4-filebeat-status.txt`
- YARA quick test:
  `yara detections/yara/suspicious_powershell.yar examples/deploy-proof/ps_example_iwr.txt > examples/deploy-proof/yara-match-ps_example.txt || true`

## Safety checklist
- Run vulnerable apps only on 127.0.0.1 or isolated VLANs
- Use DHCP reservations in pfSense instead of local static IPs where possible
- Remove real credentials from configs before committing
