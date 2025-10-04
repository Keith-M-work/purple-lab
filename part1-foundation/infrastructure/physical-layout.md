# Infrastructure Rack Setup

> All values are examples; replace with your lab specifics.

## Physical Layout (Top to Bottom)
- U1U2: Patch panel
- U3: pfSense firewall (mini PC)
- U4: Managed switch (VLAN-capable)
- U5: Raspberry Pi cluster shelf (x5)
- U6: PDU / UPS
- U7U8: Expansion

## Raspberry Pi Cluster
- 1U shelf w/ 5 slots, 280 mm active fans
- Individual PSUs, labeled power leads
- Cable color code: Red (trunk), Blue (Pi), Yellow (DMZ), Green (monitoring), Black (power)

## VLAN Layout (example)
| Role               | Switch Port | VLAN | Subnet (RFC5737)   |
|--------------------|-------------|------|--------------------|
| Vulnerable Lab     | 13         | 30   | 198.51.100.0/24    |
| Malware Lab        | 46         | 31   | 203.0.113.0/24     |
| Red Team           | 79         | 32   | 192.0.2.0/24       |
| DevOps             | 1012       | 33   | 198.51.100.0/24    |
| Honeypot           | 1315       | 34   | 203.0.113.0/24     |

## Power
- Estimated draw: ~150 W
- UPS:  500 VA (target: 30 min runtime)
