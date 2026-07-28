# Sigma Detection Rules

## Overview

Sigma rules organised by complexity, demonstrating progression in detection
engineering. Each rule maps to MITRE ATT&CK and is written against a specific,
correct logsource.

## Structure

- `1-beginner/` — basic single-event detections
- `2-intermediate/` — multi-condition rules with filters
- `3-advanced/` — behavioural detections
- `4-expert/` — multi-stage correlation

## Rules

One rule per file, and **every detection is its own folder** (base events plus
any correlation rules that consume them). pySigma resolves the `rules:`
references by `name` across a folder when you convert or `sigma check` it.

| Path | Files | Logsource | ATT&CK |
|---|---|---|---|
| `1-beginner/failed_logins/` | 3 | windows / security | T1110, T1110.003 |
| `1-beginner/powershell_download/` | 1 | windows / process_creation | T1059.001, T1105 |
| `2-intermediate/lsass_access/` | 1 | windows / process_access | T1003.001 |
| `2-intermediate/lsass_dump_tools/` | 1 | windows / process_creation | T1003.001 |
| `2-intermediate/registry_persistence/` | 1 | windows / registry_set | T1547.001 |
| `3-advanced/ransomware_behavior/` | 5 | process_creation, security, file_event | T1486, T1490 |
| `3-advanced/session_token_reuse/` | 10 | azure/signinlogs, okta, webserver | T1550.004, T1539 |
| `4-expert/apt_chain/` | 5 | wmi, security, process_access | T1546.003, T1053.005, T1003.001, T1021.002 |

**Coverage: 13 distinct ATT&CK techniques and sub-techniques across 27 rule
files in 8 detections.** Mostly Windows endpoint; `session_token_reuse/` is the
first identity/SaaS coverage. Linux is not yet implemented.

> The `session_token_reuse/` rules are deliberately the *lossy* version of that
> detection — Sigma cannot express its full condition set. See the header
> comment in `session_token_reuse/entra_signin_with_session.yml` and the
> [spec](../specs/T1550.004_session_token_reuse.md).

## Usage

`sigmac` was deprecated with the retirement of the legacy `sigmatools` package.
Current tooling is **pySigma** via **sigma-cli**.

```bash
pip install sigma-cli
sigma plugin install elasticsearch
sigma plugin install splunk
```

### Validate

```bash
sigma check .
```

### Convert to Elastic

```bash
sigma convert -t lucene -p ecs_windows 1-beginner/powershell_download/
```

### Convert to Splunk

```bash
sigma convert -t splunk -p sysmon 2-intermediate/lsass_access/
```

Convert a correlation detection by pointing the tool at its folder so the base
rules resolve:

```bash
sigma convert -t splunk -p sysmon 4-expert/apt_chain/
```

> Correlation rules (e.g. `4-expert/apt_chain/`) are only supported by backends
> that implement pySigma correlation. Splunk and ES|QL do; several others do not.
> Check backend support before depending on it.

## Testing

```bash
python ../tests/validate_sigma.py
```

The validator checks schema and field/logsource consistency. There is **no
automated harness replaying real attack telemetry** against these rules yet —
validation to date is by inspection plus manual execution of the atomics listed
in each rule's sibling platform detection under `../crowdstrike`, `../splunk`
and `../elastic`. Building that harness is tracked as open work.
