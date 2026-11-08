# 🎯 Detection Catalog

Detections written and tested in the lab, mapped to MITRE ATT&CK. Sigma rules are organized by difficulty tier; the same techniques are also implemented natively for Splunk, Elastic and CrowdStrike, and validated in CI (`.github/workflows/security-ci.yml` runs `tests/validate_sigma.py` and `tests/run_yara_tests.py` on every push and pull request to `main`, plus weekly).

**27 Sigma rules** · **14 platform-native rules, specs and signatures** · ATT&CK coverage across credential access, persistence, lateral movement, impact and session hijacking.

## Sigma rules (by tier)

| Tier | ATT&CK | Rule | Level |
|---|---|---|---|
| 🟢 Beginner | T1059.001, T1105 | [PowerShell Web Download Cradle](./sigma/1-beginner/powershell_download/powershell_download.yml) | medium |
| 🟢 Beginner | T1110 | [Brute Force - Many Failed Logons From One Source](./sigma/1-beginner/failed_logins/brute_force_many_failed_logons_from_one_source.yml) | medium |
| 🟢 Beginner | T1110 | [Failed Logon Attempt](./sigma/1-beginner/failed_logins/failed_logon_network.yml) | informational |
| 🟢 Beginner | T1110.003 | [Password Spray - One Source Against Many Accounts](./sigma/1-beginner/failed_logins/password_spray_one_source_against_many_accounts.yml) | high |
| 🟡 Intermediate | T1003.001 | [LSASS Credential Dumping via Command Line Tooling](./sigma/2-intermediate/lsass_dump_tools/lsass_dump_tools.yml) | high |
| 🟡 Intermediate | T1003.001 | [LSASS Memory Handle Access](./sigma/2-intermediate/lsass_access/lsass_access.yml) | high |
| 🟡 Intermediate | T1547.001 | [Registry Run Key Persistence](./sigma/2-intermediate/registry_persistence/registry_persistence.yml) | medium |
| 🟠 Advanced | T1486 | [Mass File Deletion Or Modification](./sigma/3-advanced/ransomware_behavior/ransomware_mass_file_access.yml) | low |
| 🟠 Advanced | T1486 | [Mass File Deletion Threshold Exceeded](./sigma/3-advanced/ransomware_behavior/mass_file_deletion_threshold_exceeded.yml) | high |
| 🟠 Advanced | T1486 | [Ransom Note File Creation](./sigma/3-advanced/ransomware_behavior/ransomware_note.yml) | high |
| 🟠 Advanced | T1486, T1490 | [Ransomware Behaviour Chain](./sigma/3-advanced/ransomware_behavior/ransomware_behaviour_chain.yml) | critical |
| 🟠 Advanced | T1490 | [Volume Shadow Copy Deletion](./sigma/3-advanced/ransomware_behavior/ransomware_shadow_delete.yml) | high |
| 🟠 Advanced | T1539, T1550.004 | [Okta Device Token Changed Mid-Session](./sigma/3-advanced/session_token_reuse/okta_device_token_changed_mid_session.yml) | critical |
| 🟠 Advanced | T1539, T1550.004 | [Session Token Used From Multiple Browsers (Entra ID)](./sigma/3-advanced/session_token_reuse/session_token_used_from_multiple_browsers_entra_id.yml) | high |
| 🟠 Advanced | T1539, T1550.004 | [Session Token Used From Multiple Browsers (Okta)](./sigma/3-advanced/session_token_reuse/session_token_used_from_multiple_browsers_okta.yml) | high |
| 🟠 Advanced | T1539, T1550.004 | [Session Token Used From Multiple Networks (Entra ID)](./sigma/3-advanced/session_token_reuse/session_token_used_from_multiple_networks_entra_id.yml) | low |
| 🟠 Advanced | T1539, T1550.004 | [Web Session Key Presented By A Non-Browser Client](./sigma/3-advanced/session_token_reuse/web_session_key_presented_by_a_non_browser_client.yml) | high |
| 🟠 Advanced | T1539, T1550.004 | [Web Session Key Used From Multiple Browsers](./sigma/3-advanced/session_token_reuse/web_session_key_used_from_multiple_browsers.yml) | high |
| 🟠 Advanced | T1539, T1550.004 | [Web Session Key Used From Multiple TLS Fingerprints](./sigma/3-advanced/session_token_reuse/web_session_key_used_from_multiple_tls_fingerprints.yml) | high |
| 🟠 Advanced | T1550.004 | [Entra ID Interactive Sign-In With Session ID](./sigma/3-advanced/session_token_reuse/entra_signin_with_session.yml) | informational |
| 🟠 Advanced | T1550.004 | [Okta Session Event](./sigma/3-advanced/session_token_reuse/okta_session_event.yml) | informational |
| 🟠 Advanced | T1550.004 | [Web Application Session Request](./sigma/3-advanced/session_token_reuse/webapp_session_request.yml) | informational |
| 🔴 Expert | T1003.001 | [LSASS Access With Unknown Call Trace](./sigma/4-expert/apt_chain/apt_chain_credential_theft.yml) | high |
| 🔴 Expert | T1021.002 | [Explicit Credential Use By Remote Execution Tooling](./sigma/4-expert/apt_chain/apt_chain_lateral_movement.yml) | medium |
| 🔴 Expert | T1053.005 | [Scheduled Task Created With Masquerading Name](./sigma/4-expert/apt_chain/apt_chain_scheduled_task.yml) | medium |
| 🔴 Expert | T1546.003 | [WMI Event Subscription Persistence](./sigma/4-expert/apt_chain/apt_chain_wmi_persistence.yml) | medium |
| 🔴 Expert | chain | [APT Activity Chain - Persistence Then Credential Theft Then Lateral Movement](./sigma/4-expert/apt_chain/apt_activity_chain_persistence_then_credential_theft_then_lateral_movement.yml) | critical |

## Same techniques, native platforms

**📐 Detection specs (design docs):** [T1550.004_session_token_reuse.md](./specs/T1550.004_session_token_reuse.md)

**Splunk SPL:** [T1003.001_lsass_credential_dump.spl](./splunk/T1003.001_lsass_credential_dump.spl) · [T1550.004_session_token_reuse.spl](./splunk/T1550.004_session_token_reuse.spl)

**Elastic (EQL/TOML):** [T1003.001_lsass_credential_dump.md](./elastic/T1003.001_lsass_credential_dump.md) · [T1003.001_lsass_credential_dump.toml](./elastic/T1003.001_lsass_credential_dump.toml) · [T1550.004_session_token_reuse.md](./elastic/T1550.004_session_token_reuse.md)

**CrowdStrike (LogScale/CQL):** [T1003.001_lsass_credential_dump.md](./crowdstrike/T1003.001_lsass_credential_dump.md) · [T1550.004_session_token_reuse.md](./crowdstrike/T1550.004_session_token_reuse.md)

**YARA:** [cobalt_strike.yar](./yara/cobalt_strike.yar) · [embedded_mimikatz_like.yar](./yara/embedded_mimikatz_like.yar) · [ransomware_generic.yar](./yara/ransomware_generic.yar) · [suspicious_powershell.yar](./yara/suspicious_powershell.yar)

**Wazuh rules:** [c2_patterns.xml](./wazuh/c2_patterns.xml) · [local_rules.xml](./wazuh/local_rules.xml)

## How these are tested

- `tests/validate_sigma.py` / `validate_sigma_enhanced.py`: schema and field validation for every Sigma rule
- `tests/run_yara_tests.py`: YARA rules run against benign test strings in `tests/test_data/`
- Both run in GitHub Actions on pushes and pull requests to `main`, plus a weekly schedule (see the CI badge on the main README).
