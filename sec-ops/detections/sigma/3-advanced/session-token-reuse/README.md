# Session Token Reuse Across Browsers / Locations — T1550.004

Detects a single authenticated session identifier being presented from more
than one browser, network, TLS stack, or device inside a short window — the
observable signature of **stolen-session-token replay** (AiTM phishing,
infostealer cookie theft, token replay). MFA does not prevent it: the stolen
token is already authenticated. **Respond by revoking the session, not by
resetting the password.**

Spec: `../../specs/T1550.004_session_token_reuse.md` (external to this repo).

## Rules in this folder

| File | Type | Level | Fires on |
|------|------|-------|----------|
| `entra_signin_with_session.yml` | base | informational | successful browser Entra sign-in with a session id |
| `entra_session_multi_browser.yml` | value_count | high | one SessionId, ≥2 browsers / 1h |
| `entra_session_multi_network.yml` | value_count | low | one SessionId, ≥2 ASNs / 1h |
| `okta_session_event.yml` | base | informational | successful Okta event with an external session id |
| `okta_session_multi_browser.yml` | value_count | high | one externalSessionId, ≥2 browsers / 1h |
| `okta_session_dthash_change.yml` | value_count | critical | one externalSessionId, ≥2 device tokens / 1h |
| `webapp_session_request.yml` | base | informational | authenticated web request with a session key |
| `webapp_session_multi_ja4.yml` | value_count | high | one session_key, ≥2 JA4 fingerprints / 1h |
| `webapp_session_multi_browser.yml` | value_count | high | one session_key, ≥2 User-Agents / 1h |
| `webapp_session_nonbrowser_client.yml` | single event | high | session key presented by curl/python/etc. |

The base rules carry a `name:` and never alert; each correlation references its
base by that name.

## What Sigma can and cannot express here — read before deploying

**Expressible:** same session id, same user, ≥2 distinct browsers, a time
window. A `value_count` correlation over the session id counting distinct
browser values is exactly that.

**NOT expressible — R3 AND R4 in one rule.** Sigma's `value_count` takes a
single `field:`, so one rule counts distinct browsers *or* distinct ASNs, not
both with an AND between them. The Entra browser and network variants are
provided as a pair: run them together and **intersect on SessionId at the
backend**, or use the native SPL / ES|QL / CQL implementations under
`../../{splunk,elastic,crowdstrike}/`, which express R3 AND R4 in one pass.
On its own the network variant is noisy (hence `level: low`); the browser
variant already stands alone at `high`.

**NOT expressible — normalisation and enrichment.** These must happen in the
ingest pipeline *before* the rules run. This is the part that decides whether
the rules are usable or a false-positive generator:

- **Browser-family normalisation (Entra, web).** `DeviceDetail.browser` is
  `"Chrome 126.0.0"` and `cs-user-agent` is a full UA string. Without
  collapsing them to a family (`Chrome`), every auto-update reads as a second
  browser and the multi-browser rules fire on it. This is the dominant FP.
  *Okta is exempt* — `client.userAgent.browser` is already family-level
  (`CHROME`, `SAFARI`).
- **ASN enrichment (Entra network).** Entra sign-in logs have no ASN. The
  pipeline must map `IPAddress -> AutonomousSystemNumber` and stamp it on the
  event, or `entra_session_multi_network` counts a field that isn't there and
  never fires.
- **Session-key hashing (web).** HMAC-hash the session cookie at the reverse
  proxy before indexing. Session tokens are credentials; indexing them raw
  turns the SIEM into a credential store.

Treat these Sigma rules as the portable, lossy version. Where you have the
choice, deploy the platform-native implementations.

## Why the levels differ (signal-to-noise)

Rule severity tracks expected signal-to-noise, not just impact:

- `critical` — **dtHash change** (Okta). A device-token change under a constant
  session id has no benign explanation; investigate every hit.
- `high` — **multi-browser** and **JA4 mismatch**. Strong once normalisation is
  in place; a browser cookie does not move between browsers or TLS stacks.
- `low` — **multi-network** alone. VPNs, mobile carriers and iCloud Private
  Relay all move a user between ASNs legitimately. It is a supporting signal for
  the intersection, not a standalone alert.

## Detection lifecycle

All rules ship `status: experimental`. Promote to `test`, then `stable`, only
after validating against real telemetry and confirming the normalisation and
enrichment above are live — otherwise the multi-browser rules will fire on
routine auto-updates. Tune the false-positive lists per environment as you go.

## Evasion note — prefer JA4 over User-Agent

A competent attacker replaying a stolen cookie copies the victim's User-Agent
verbatim, and malware routinely presents an otherwise-normal UA to evade
inspection, so the User-Agent is effectively attacker-controlled. JA4
fingerprints the actual TLS ClientHello and cannot be spoofed by copying a
string. Where TLS fingerprints are available, `webapp_session_multi_ja4` is the
stronger control and `webapp_session_multi_browser` is the fallback.

## Complementary endpoint control

For on-host sessions, correlate Windows logon/logoff by Logon ID (4624/4672
paired with 4634/4647) to model session lifetime. It does not cover cloud token
replay but is a useful cross-check when a suspect session maps back to a
specific host.

## Validate

```bash
python sec-ops/detections/tests/validate_sigma.py
python sec-ops/detections/tests/validate_sigma_enhanced.py   # from repo root
```

Both validators understand correlation rules (a document with a `correlation:`
block and no `detection`/`logsource`) and multi-document files. If you have the
Sigma CLI:

```bash
sigma check .
sigma convert -t splunk entra_session_multi_browser.yml   # correlation support varies by backend
```
