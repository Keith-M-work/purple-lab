# C2 Detection Engineering

##  IMPORTANT: Lab Use Only
This section focuses on DETECTING C2 traffic, not operating C2 frameworks.

## Purpose
- Understand C2 behavioral patterns for detection
- Test detection rules against simulated traffic
- NO operational C2 guidance provided

## Network Isolation Requirements
- Dedicated VLAN with NO internet access
- Deny-all egress by default
- Only allow specific replay sources

## Content Structure
- `havoc/` - Detection signatures and IOCs
- `sliver/` - Detection signatures and IOCs  
- `simulations/` - Safe traffic replay and beacon simulators

## Detection Focus Areas
1. Periodic callbacks (beaconing)
2. Unusual user agents
3. Non-standard ports
4. Living-off-the-land binaries
5. Process ancestry anomalies
