# ClawArmor 架构设计文档

## 项目概述

ClawArmor 是专为 OpenClaw（小龙虾）框架设计的新一代 Agent 运行时安全插件。继承 ClawAegis 的"纵深防御"基因，融合"语义意图对齐"思想，构建"快-慢双引擎"防御体系。

**安装命令**：`openclaw plugins install ClawArmor`
**卸载命令**：`openclaw plugins uninstall ClawArmor`

---

## 技术栈

| 层次 | 技术 |
|------|------|
| 语言 | TypeScript（ES Module） |
| 测试 | Vitest 4.x |
| 运行时 | Node.js 22+ |
| 外部依赖 | 无生产依赖（零依赖设计） |
| 本地模型 | Ollama（可选） |
| 云端模型 | DeepSeek / Kimi / OpenAI 兼容协议（可选） |

---

## 核心架构：快-慢双引擎

```
用户请求
    │
    ▼
┌─────────────────────────────────────────────────────┐
│                 OpenClaw 框架                         │
│  9个生命周期 Hook 节点                                 │
└────────────────────────┬────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│                 ClawArmor 核心调度层                   │
│              (src/core-hooks/handlers.ts)             │
└──────────────┬──────────────────┬──────────────────┘
               │                  │
               ▼                  ▼
  ┌────────────────────┐  ┌────────────────────────┐
  │  Fast Path         │  │  Slow Path             │
  │  静态规则引擎        │  │  动态旁路验证引擎        │
  │                    │  │                        │
  │ • Shell 注入检测    │  │ • 意图一致性验证         │
  │ • 资产沙箱隔离      │  │ • 控制流完整性检查       │
  │ • 编码混淆检测      │  │ • 数据流机密性熔断       │
  │ • 污点追踪          │  │                        │
  │ • PII 快速预筛      │  │  模型网关               │
  │ • 记忆审计          │  │  ├── Ollama（本地）      │
  │ • 输出脱敏          │  │  └── OpenAI Compat     │
  └────────────────────┘  └────────────────────────┘
```

---

## 五层防御模型

| 层次 | 名称 | 防御目标 | 引擎 |
|------|------|----------|------|
| 1 | 基础扫描层 | Skill 投毒、环境篡改 | Fast |
| 2 | 感知输入层 | 直接/间接提示词注入 | Fast + Slow |
| 3 | 认知状态层 | memory_store 污染、记忆投毒 | Fast |
| 4 | 决策对齐层 | 意图劫持、工作流劫持 | **Slow（核心创新）** |
| 5 | 执行控制层 | 高危 Shell、SSRF、数据外带 | Fast + Slow |

---

## 模块划分

```
ClawArmor/
├── src/
│   ├── engine-fast/           # Fast Path：静态规则引擎（源自 ClawAegis）
│   │   ├── rules.ts           # 核心规则：提示词注入、密钥外泄、危险 Shell
│   │   ├── security-strategies.ts  # 防御策略集（10层策略）
│   │   ├── command-obfuscation.ts  # 命令混淆检测（29个Unicode + 15种模式）
│   │   ├── encoding-guard.ts  # 编码载荷检测（base64/hex/base32/url）
│   │   ├── scan-service.ts    # Skill 文件扫描服务（Worker 线程）
│   │   └── scan-worker.ts     # Worker 线程：Skill 文本分析
│   │
│   ├── engine-slow/           # Slow Path：动态旁路验证引擎（ClawArmor 创新）
│   │   ├── gateway/
│   │   │   ├── ollama.ts      # Ollama 本地模型适配器
│   │   │   ├── openai-compat.ts    # OpenAI 兼容协议适配器
│   │   │   └── index.ts       # 模型路由网关（fail-open 设计）
│   │   └── checkers/
│   │       ├── intent-alignment.ts  # 基准意图追踪 + 语义比对
│   │       ├── control-flow.ts      # 工具调用链非法路径检测
│   │       └── data-flow.ts         # PII/凭证外泄熔断
│   │
│   ├── core-hooks/            # 9个 OpenClaw 生命周期 Hook
│   │   └── handlers.ts        # 双引擎串联调度
│   │
│   ├── taint-tracker/         # 污点标记与传播追踪
│   │   └── index.ts
│   │
│   ├── types/                 # 统一类型定义
│   │   └── index.ts
│   │
│   ├── config/                # 配置解析器
│   │   └── index.ts
│   │
│   └── state.ts               # 安全状态管理（继承自 ClawAegis）
│
├── prompts/                   # 验证场景 System Prompts
│   ├── intent-alignment.md    # 意图对齐验证提示词
│   ├── control-flow.md        # 控制流完整性提示词
│   └── data-flow.md           # 数据流机密性提示词
│
├── tests/
│   ├── engine-fast/           # Fast Path 单元测试
│   ├── engine-slow/           # Slow Path 单元测试（mock 模型）
│   └── integration/           # 端到端场景测试
│
├── docs/                      # 文档
├── index.ts                   # 插件入口（OpenClaw 标准注册格式）
└── runtime-api.ts             # OpenClaw Plugin API 类型声明
```

---

## 9个生命周期 Hook

| Hook | 触发时机 | 防御动作 |
|------|----------|----------|
| `agent_start` | Agent 启动 | 捕获基准意图、初始化污点追踪 |
| `skill_load`（via `agent_start`） | Skill 加载 | Skill 投毒检测、受保护 Skill 拦截 |
| `before_tool_call` | 工具调用前 | 资产沙箱 + 污点校验 + 数据流熔断 |
| `after_tool_call` | 工具返回后 | 外部结果打污点 + 注入模式扫描 |
| `before_prompt_build` | 规划生成后 | **意图对齐验证（Slow Path）** + Prompt 安全注入 |
| `memory_read`（via 工具拦截） | 读记忆前 | 记忆完整性检查 |
| `memory_write`（via 工具拦截） | 写记忆前 | 大小限制 + 注入模式审计 |
| `before_message_write` | 输出前 | PII/API Key 脱敏 |
| `agent_end` + `session_end` | 结束/清理 | 状态清理、污点注册表清除 |

---

## 数据持久化方案

| 数据 | 存储位置 | 格式 |
|------|----------|------|
| 受信 Skill 记录 | `~/.openclaw/state/plugins/claw-armor/trusted-skills.json` | JSON |
| 自完整性记录 | `~/.openclaw/state/plugins/claw-armor/self-integrity.json` | JSON |
| 内存态安全状态 | 进程内 Map（TTL=5min） | 内存 |
| 污点注册表 | 进程内 Map（会话级） | 内存 |
| 基准意图 | 进程内 Map（会话级） | 内存 |

---

## 配置示例（clawarmor.json）

```json
{
  "allDefensesEnabled": true,
  "defaultBlockingMode": "enforce",
  "protectedPaths": [
    "/etc",
    "~/.ssh"
  ],
  "slowEngine": {
    "enabled": true,
    "mode": "ollama",
    "ollamaBaseUrl": "http://localhost:11434",
    "ollamaModel": "llama3",
    "intentAlignmentEnabled": true,
    "controlFlowCheckEnabled": true,
    "dataFlowCheckEnabled": true,
    "timeoutMs": 10000
  },
  "taintTrackingEnabled": true
}
```

---

## 日志机制

### 设计目标

结构化日志、零生产依赖、可测试性强。所有模块共用同一 `ArmorLogger` 树，每个子模块通过 `logger.child({ module: "xxx" })` 获得带作用域的子日志器。

### 层次结构

```
ArmorLogger（根，由 fromAegisLogger 桥接 OpenClaw 注入的 logger）
  ├── child({ module: "hooks" })          ← handlers.ts
  ├── child({ module: "skill-watcher" })  ← skill-watcher.ts
  ├── child({ module: "session-state" })  ← session-state.ts
  └── forSession(sessionKey)              ← 携带 session 上下文
```

### 日志级别

| 级别 | 场景 |
|------|------|
| `trace` | 细粒度调试（逐 token 分析） |
| `debug` | 模块内部流程跟踪 |
| `info` | 插件启动/关闭、关键状态变化 |
| `warn` | 安全告警（触发规则但未阻断） |
| `error` | 阻断性错误、不可恢复异常 |

### 安全事件类型（SecurityEventType）

在 `warn`/`error` 基础上额外打 `securityEvent` 字段，便于 SIEM 聚合：

```
injection-detected | intent-hijacked | taint-violation
data-exfiltration | output-redacted | skill-risk
shell-obfuscation | payload-encoded | memory-guard
loop-detected | protected-path
```

### 传输器（Transports）

| 传输器 | 用途 |
|--------|------|
| `ConsoleTransport` | 开发调试，pretty 彩色或 JSON 格式 |
| `FileTransport` | 生产日志采集，带缓冲写入和轮转 |
| `MemoryTransport` | 测试专用，捕获所有日志条目 |

### 测试工具

```typescript
import { createTestLogger } from "./tests/utils/test-logger.js";

const { logger, logs, assert } = createTestLogger();
// 注入到被测模块，断言安全事件是否触发
assert.hasSecurityEvent("injection-detected"); // true/false
assert.hasWarn();                               // true/false
logs.getByLevel("warn");                        // LogEntry[]
```

### AegisLogger 兼容桥接

OpenClaw 注入的 `api.logger` 是简化接口，通过 `fromAegisLogger()` 包装为 `ArmorLogger`，保留结构化日志能力，且在反向场景（模块需要旧接口）通过 `toAegisLogger()` 导出兼容对象。

---

## 已知限制与取舍

1. **Slow Path 可选性**：意图对齐依赖外部/本地模型，禁用时退化为纯规则引擎（ClawAegis 同等能力）
2. **Fail-open 设计**：所有 Slow Path 调用失败时自动放行，保障业务连续性
3. **污点追踪精度**：基于字符串指纹匹配，对经过多次变换的污点数据可能漏检

---

## 后续扩展计划

- [ ] 支持从外部 JSON 文件动态加载规则
- [ ] 添加 OpenTelemetry 可观测性接口
- [ ] 支持多租户隔离的安全策略
- [ ] 提供 Web UI 配置面板
