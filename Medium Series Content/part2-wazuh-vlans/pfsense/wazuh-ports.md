# pfSense Rules for Wazuh
- UDP 1514  WAZUH_MGR_IP (events)
- TCP 1515  WAZUH_MGR_IP (enrollment)
- Optional: TCP 443/9200/55000

### Test from Pi
nc -u -zv WAZUH_MGR_IP 1514
nc -zv WAZUH_MGR_IP 1515
curl -k https://WAZUH_MGR_IP:443/ -I
