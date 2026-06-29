# Contributing to ClawArmor

Thanks for helping improve ClawArmor. This project focuses on practical runtime defenses for AI agents, so contributions should be evidence-driven and easy to verify.

## Good First Contributions

- Add regression tests for a prompt-injection or command-bypass pattern
- Improve documentation for a defense layer
- Add safe examples for `claw-armor.config.json`
- Reduce false positives with tests that prove the intended behavior
- Improve logs, diagnostics, or manual verification steps

## Development Setup

Requirements:

- Node.js 22+
- npm

Install dependencies:

```bash
npm install
```

Run the core checks:

```bash
npm run typecheck
npm test
npm run build
```

## Pull Request Expectations

Before opening a PR:

- Keep the change narrowly scoped.
- Add or update tests for behavior changes.
- Update `README.md`, `docs/changelog.md`, or `docs/manual-test-guide.md` when the user-facing behavior changes.
- Avoid committing local config, credentials, logs, or generated temporary files.
- For security changes, describe the defended path and the bypass or regression being addressed.

PRs should include:

- Problem statement
- Summary of the change
- Verification commands and results
- Security impact, if any
- Compatibility or migration notes, if any

## Security-Sensitive Changes

For changes to rule matching, prompt injection handling, tool interception, taint tracking, output redaction, or slow-engine prompts:

- Include at least one positive test that must be blocked or flagged.
- Include at least one negative test when false positives are plausible.
- Explain whether the layer should `enforce`, `observe`, or only log.
- Document any fail-open behavior.

## Style

- Prefer explicit, readable TypeScript over clever abstractions.
- Keep security rules named and traceable.
- Separate detection, decision, and logging where practical.
- Mark uncertain behavior as best effort instead of overstating protection.

## Responsible Disclosure

If your contribution describes a new exploitable bypass, follow `SECURITY.md` instead of opening a public issue with exploit details.
