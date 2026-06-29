# Security Policy

ClawArmor is a security-focused OpenClaw plugin. Please report suspected bypasses, unsafe defaults, prompt-injection gaps, command-execution escapes, data-exfiltration paths, or sensitive-data handling issues responsibly.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.3.x | Yes |
| < 1.3 | Best effort |

## Reporting a Vulnerability

If the issue may expose credentials, enable arbitrary command execution, bypass a protection layer, or disclose private data, do not open a public issue with exploit details.

Preferred reporting path:

1. Open a private GitHub security advisory for this repository if available.
2. If private advisories are unavailable, create a public issue with a minimal title such as `Security report: ClawArmor bypass` and omit exploit payloads. The maintainer will move the discussion to a private channel.

Please include:

- ClawArmor version or commit SHA
- OpenClaw version, Node.js version, and operating system
- Relevant configuration with secrets removed
- Which defense layer was expected to trigger
- Minimal reproduction steps or redacted payload samples
- Observed behavior and expected behavior

## Handling Timeline

- Initial triage target: 7 days
- Fix target for confirmed high-impact issues: 30 days when feasible
- Disclosure: after a fix or mitigation is available, unless coordinated otherwise

## Scope

In scope:

- Prompt-injection or indirect-injection bypasses
- Dangerous command or script-provenance bypasses
- Taint-tracking and data-exfiltration misses
- Output redaction failures for supported sensitive data types
- Unsafe defaults or configuration precedence bugs
- Security regressions in hooks, rule compilation, and slow-engine checks

Out of scope:

- Attacks requiring disabled defenses unless the documentation claims protection
- Issues in upstream OpenClaw outside ClawArmor's integration surface
- Denial-of-service reports without a practical security impact
- Reports based only on theoretical risk without a reproduction path

## Safe Testing

Use local sandboxes and test fixtures. Do not test against systems, credentials, or data that you do not own or have permission to assess.
