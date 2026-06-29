# Roadmap

ClawArmor's goal is to become a practical, testable security layer for AI agent runtimes. The roadmap favors measurable defenses, reproducible tests, and maintainable defaults.

## Current Focus

- Keep Fast Path defenses reliable with low latency and no production dependencies.
- Improve evidence-driven prompt-injection, command, data-flow, and output-redaction tests.
- Make configuration safe by default while keeping emergency overrides simple.
- Document how maintainers can verify security behavior before releases.

## Near Term

### 1. Release and Maintenance Hygiene

- Publish tagged releases with changelog excerpts.
- Add release verification checklist.
- Keep package, plugin manifest, and changelog versions aligned.
- Add GitHub Actions for typecheck, tests, and build.

### 2. Security Coverage

- Expand regression tests for indirect prompt injection through tool results.
- Add more shell-obfuscation and encoded-payload fixtures.
- Add negative tests for safe commands and benign content.
- Track false positives by defense layer.

### 3. OpenClaw Integration

- Validate hook behavior against current OpenClaw releases.
- Document compatibility boundaries and known upstream assumptions.
- Add installation and upgrade examples for common OpenClaw setups.

### 4. Codex-Assisted Maintenance

- Use Codex for PR review, issue triage, release-note drafting, and security regression analysis.
- Use Codex Security for deeper review of rule bypasses, unsafe defaults, data-flow gaps, and release candidates.
- Publish reusable maintenance prompts and review checklists for other OSS agent-security projects.

## Longer Term

- Policy packs for different security profiles, such as local-only, enterprise, research, and high-risk automation.
- Structured security benchmark suite for agent runtime defenses.
- Better observability outputs for SIEM and incident-response workflows.
- Optional signed rule packs or provenance metadata for custom threat patterns.

## Non-Goals

- Replace upstream OpenClaw authorization and sandboxing.
- Promise complete prevention of all prompt-injection attacks.
- Depend on a single hosted LLM provider for core enforcement.
- Add broad platform features unrelated to runtime security.
