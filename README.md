# ClawArmor

English | [中文](README.zh-CN.md)

ClawArmor is a security plugin for [OpenClaw](https://github.com/antgroup/openclaw). It adds runtime defenses for AI agents that can read files, call tools, run shell commands, persist memory, and consume untrusted external content.

The project focuses on practical agent security: prompt injection, data exfiltration, tool abuse, script provenance, taint tracking, output redaction, and intent alignment.

## Why This Matters

AI agent frameworks expose high-impact capabilities to model-driven workflows. A malicious web page, tool result, document, or memory entry can try to steer an agent into reading secrets, running commands, disabling protections, or sending private data to an attacker.

ClawArmor turns those risks into testable runtime controls:

- Block dangerous commands, protected paths, and suspicious write-then-execute flows before tool execution.
- Neutralize embedded prompt injection from tool results before persistence.
- Track untrusted external data and flag risky flows into privileged tools.
- Redact secrets and personal data before model output or transcript persistence.
- Add structured logs and test fixtures so maintainers can review security behavior before releases.

ClawArmor also serves as a reference implementation for OSS maintainers building agent security checks, rule packs, and release verification workflows.

## Features

| Feature | What it does |
| --- | --- |
| Defense in depth | Covers user input, tool calls, tool results, memory, output, and intent checks |
| Intent alignment | Compares the user's baseline intent with the agent's current plan and tool history |
| Taint tracking | Marks untrusted external data and prevents unsafe use in privileged tools |
| Encoded payload scanning | Recursively decodes base64, hex, base32, and URL-encoded payloads |
| Shell obfuscation detection | Detects invisible Unicode characters and suspicious shell composition |
| Model gateway | Supports local Ollama and OpenAI-compatible APIs for optional slow checks |
| Structured security logs | Emits named security events for debugging and SIEM-style collection |
| Zero production dependencies | Uses Node.js and TypeScript without runtime npm dependencies |
| Fail-open slow path | Lets the fast rules protect core flows while optional LLM checks fail open |
| Dedicated config | Uses `claw-armor.config.json` without polluting `openclaw.json` |

## Install

```bash
openclaw plugins install ClawArmor
```

To uninstall:

```bash
openclaw plugins uninstall ClawArmor
```

After installation, copy the config template into the user plugin directory:

```bash
mkdir -p ~/.openclaw/plugins/claw-armor
cp /path/to/ClawArmor/claw-armor.config.json ~/.openclaw/plugins/claw-armor/
```

Then edit:

```text
~/.openclaw/plugins/claw-armor/claw-armor.config.json
```

## Configuration

ClawArmor reads its main configuration from `claw-armor.config.json`.

Lookup order:

| Priority | Path | Use |
| --- | --- | --- |
| 1 | `~/.openclaw/plugins/claw-armor/claw-armor.config.json` | Recommended user config |
| 2 | `~/.openclaw/extensions/claw-armor/claw-armor.config.json` | Installed plugin config |
| 3 | `{working-directory}/claw-armor.config.json` | Development and debugging |

If no file exists, ClawArmor uses built-in defaults: Fast Path defenses on, `enforce` as the default blocking mode, and Slow Path disabled.

Core top-level fields:

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `version` | string | `"1"` | Config schema version |
| `allDefensesEnabled` | boolean | `true` | Master switch |
| `defaultBlockingMode` | `"enforce"` \| `"observe"` \| `"off"` | `"enforce"` | Default mode for defenses without an explicit mode |

Minimal Fast Path config:

```json
{
  "version": "1",
  "allDefensesEnabled": true,
  "defaultBlockingMode": "enforce",
  "fastPath": {
    "selfProtection": {
      "enabled": true,
      "mode": "enforce",
      "protectedPaths": ["~/.ssh", "/etc", "~/secrets"]
    },
    "taintTracking": { "enabled": true }
  },
  "slowEngine": { "enabled": false, "model": { "provider": "disabled" } },
  "customThreatPatterns": {}
}
```

Local model Slow Path:

```json
{
  "version": "1",
  "allDefensesEnabled": true,
  "defaultBlockingMode": "enforce",
  "fastPath": {
    "selfProtection": { "enabled": true, "mode": "enforce", "protectedPaths": [] }
  },
  "slowEngine": {
    "enabled": true,
    "intentAlignment": { "enabled": true },
    "controlFlowCheck": { "enabled": true },
    "dataFlowCheck": { "enabled": true },
    "model": {
      "provider": "ollama",
      "ollama": {
        "baseUrl": "http://localhost:11434",
        "model": "llama3",
        "timeoutMs": 10000
      }
    }
  },
  "customThreatPatterns": {}
}
```

OpenAI-compatible Slow Path:

```json
{
  "version": "1",
  "allDefensesEnabled": true,
  "slowEngine": {
    "enabled": true,
    "intentAlignment": { "enabled": true },
    "model": {
      "provider": "openai-compat",
      "openaiCompat": {
        "baseUrl": "https://api.deepseek.com/v1",
        "model": "deepseek-chat",
        "apiKeyEnvVar": "DEEPSEEK_API_KEY",
        "timeoutMs": 15000
      }
    }
  },
  "customThreatPatterns": {}
}
```

## Defense Layers

### Fast Path

Fast Path runs static checks with low latency.

| Layer | What it checks |
| --- | --- |
| `selfProtection` | SSH keys, system files, OpenClaw paths, and custom protected paths |
| `commandBlock` | `rm -rf`, fork bombs, remote pipe execution, plugin disabling, and shell obfuscation |
| `encodingGuard` | Encoded malicious payloads |
| `scriptProvenanceGuard` | Suspicious write-then-execute flows within one run |
| `memoryGuard` | Large or instruction-like `memory_store` writes |
| `loopGuard` | Repeated high-risk tool calls in one run |
| `exfiltrationGuard` | Source to transform to sink data-exfiltration chains |
| `userRiskScan` | User-input jailbreak and prompt-injection markers |
| `toolResultScan` | Embedded injection instructions in tool results |
| `outputRedaction` | API keys, bearer tokens, phone numbers, ID numbers, bank cards, IMSI, and internal IPs |
| `promptGuard` | System-level safety rules injected before model calls |
| `taintTracking` | External data flowing into privileged tools |
| `skillScan` | Risky instructions inside skill files |

### Slow Path

Slow Path is optional and runs semantic checks through a local or OpenAI-compatible model gateway.

| Checker | What it checks |
| --- | --- |
| Intent alignment | Whether the agent's plan still matches the user's original request |
| Control-flow integrity | Whether untrusted data drives privileged behavior |
| Data-flow confidentiality | Whether private data may leave to an untrusted destination |

### Defense Modes

| Mode | Behavior |
| --- | --- |
| `enforce` | Block the tool call and return the reason |
| `observe` | Log and inject warning context without blocking |
| `off` | Disable the layer |

## Custom Threat Patterns

You can extend built-in regular-expression rules without changing TypeScript source code.

Supported groups:

- `customThreatPatterns.protectedPaths`
- `customThreatPatterns.dangerousCommands`
- `customThreatPatterns.sensitiveDataRedaction`
- `customThreatPatterns.injectionDetection`

Example:

```json
{
  "customThreatPatterns": {
    "protectedPaths": [
      {
        "id": "k8s-config",
        "regex": "(?:^|/)\\.kube/config(?:$|/)",
        "description": "Protect Kubernetes config"
      }
    ],
    "dangerousCommands": [
      {
        "id": "drop-db",
        "regex": "DROP\\s+(?:DATABASE|TABLE)\\s+",
        "description": "Block SQL DROP commands"
      }
    ],
    "sensitiveDataRedaction": [
      {
        "id": "internal-key",
        "regex": "CORP_API_[A-Za-z0-9]{32,}",
        "description": "Redact internal API keys"
      }
    ],
    "injectionDetection": [
      {
        "id": "developer-mode",
        "regex": "enter developer mode",
        "description": "Detect a custom jailbreak phrase"
      }
    ]
  }
}
```

Invalid regular expressions fail open and do not stop plugin startup.

## Project Structure

```text
ClawArmor/
├── claw-armor.config.json
├── openclaw.plugin.json
├── index.ts
├── runtime-api.ts
├── src/
│   ├── config/
│   ├── engine-fast/
│   ├── engine-slow/
│   ├── logger/
│   ├── core-hooks/
│   ├── taint-tracker/
│   ├── session-state.ts
│   └── types/
├── tests/
├── prompts/
└── docs/
```

## Known Limitations

### Long single-session test runs

OpenClaw GUI may stop responding after several consecutive security test cases in the same session. Repeated warnings and injected safety context can consume the model context window, especially with smaller-context models.

Use `/reset` between groups of manual tests.

### Streaming output and transcript hooks

`tool_result_persist` and `before_message_write` modify transcript storage. They do not modify tokens that have already streamed to a UI. ClawArmor also injects Prompt Guard rules before model generation so the model redacts sensitive data before streaming when possible.

## Development

Requirements:

- Node.js 22+
- TypeScript 5.5+

Common commands:

```bash
npm install
npm run typecheck
npm test
npm run build
```

Release verification:

```bash
npm run typecheck
npm test
npm run build
```

See [docs/release-checklist.md](docs/release-checklist.md).

## Logging

ClawArmor emits structured logs with a `securityEvent` field.

Example startup log:

```text
[ClawArmor] Plugin started {
  configFile: "/Users/you/.openclaw/plugins/claw-armor/claw-armor.config.json",
  slowEngineEnabled: false,
  slowEngineMode: "disabled",
  taintTrackingEnabled: true,
  customPatternCounts: { protectedPaths: 2, dangerousCommands: 1, sensitiveRedaction: 0, injectionDetection: 0 }
}
```

Common event names include `injection-detected`, `intent-hijacked`, `taint-violation`, `data-exfiltration`, `output-redacted`, `skill-risk`, `shell-obfuscation`, `payload-encoded`, `memory-guard`, `loop-detected`, and `protected-path`.

## OSS Maintenance

- License: [MIT](LICENSE)
- Security policy: [SECURITY.md](SECURITY.md)
- Contributing guide: [CONTRIBUTING.md](CONTRIBUTING.md)
- Roadmap: [ROADMAP.md](ROADMAP.md)
- Release checklist: [docs/release-checklist.md](docs/release-checklist.md)

## Codex Maintenance Plan

The maintainer uses Codex for:

- PR review focused on rule bypasses, config regressions, missing tests, and false positives.
- Security review for prompt injection, command execution, taint propagation, data exfiltration, and output redaction.
- Issue triage across bugs, false positives, hardening requests, and documentation gaps.
- Release preparation, changelog summaries, and security checklist review.

## Documentation

- Architecture: [docs/architecture.md](docs/architecture.md)
- Manual testing: [docs/manual-test-guide.md](docs/manual-test-guide.md)
- Changelog: [docs/changelog.md](docs/changelog.md)
- Chinese README: [README.zh-CN.md](README.zh-CN.md)
