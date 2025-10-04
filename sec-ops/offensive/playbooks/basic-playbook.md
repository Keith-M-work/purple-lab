# Red Team Playbook (Lab)
Recon:
  nmap -sV -sC -oA recon TARGET_IP
  dirb http://TARGET_IP:3000
  nikto -h http://TARGET_IP:3000
Scenarios: sqli, xss, weak auth (for detection)
