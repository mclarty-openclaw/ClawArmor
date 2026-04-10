# ClawArmor 架构设计文档

**当前版本：** v1.3.5
**更新日期：** 2026-04-10

## 项目概述

ClawArmor 是专为 OpenClaw（小龙虾）框架设计的新一代 Agent 运行时安全插件。继承 ClawAegis 的"纵深防御"基因，融合"语义意图对齐"思想，构建"快-慢双引擎"防御体系。

**安装命令**：`openclaw plugins install ClawArmor`
**卸载命令**：`openclaw plugins uninstall ClawArmor`

---

## 技术栈

| 层次 | 技术 |
|------|------|
| 语言 | TypeScript（ES Module，`tsc` 编译到 `dist/`） |
| 测试 | Vitest 4.x（165 个单元测试，v1.3.5 全量通过） |
| 运行时 | Node.js 22+ |
| 外部依赖 | 无生产依赖（零依赖设计） |
| 本地模型 | Ollama（可选，数据不出域场景） |
| 云端模型 | DeepSeek / Kimi / OpenAI 兼容协议（已验证 DeepSeek `deepseek-chat`） |

---

## 核心架构：快-慢双引擎

```
用户请求
    │
    ▼
┌──────────────────────────────────────────────────────┐
│                  OpenClaw 框架                         │
│   9 个生命周期 Hook 节点（agent_start → session_end）   │
└─────────────────────┬────────────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────────────────┐
│              ClawArmor 核心调度层                       │
│         index.ts（Hook 注册）                          │
│         src/core-hooks/handlers.ts（双引擎串联）         │
└──────────────┬────────────────────┬──────────────────┘
               │                    │
               ▼                    ▼
  ┌─────────────────────┐  ┌──────────────────────────┐
  │  Fast Path           │  │  Slow Path               │
  │  静态规则引擎          │  │  动态旁路验证引擎           │
  │  (engine-fast/)      │  │  (engine-slow/)           │
  │                      │  │                          │
  │ • Shell 注入检测      │  │ • 意图一致性验证           │
  │ • 资产沙箱隔离        │  │ • 控制流完整性检查         │
  │ • 编码混淆检测        │  │ • 数据流机密性熔断         │
  │ • 污点追踪            │  │                          │
  │ • PII 快速检测        │  │  模型网关 (gateway/)      │
  │ • 记忆审计            │  │  ├── Ollama（本地）        │
  │ • 输出脱敏            │  │  └── OpenAI Compat       │
  │ • 工具结果注入净化     │  │                          │
  └─────────────────────┘  └──────────────────────────┘
```

---

## 五层防御模型

| 层次 | 名称 | 防御目标 | 引擎 |
|------|------|----------|------|
| 1 | 基础扫描层 | Skill 投毒、环境篡改 | Fast |
| 2 | 感知输入层 | 直接/间接提示词注入、工具结果嵌入注入 | Fast + Slow |
| 3 | 认知状态层 | `memory_store` 污染、记忆投毒 | Fast |
| 4 | 决策对齐层 | 意图劫持、工作流劫持 | **Slow（核心创新）** |
| 5 | 执行控制层 | 高危 Shell、SSRF、数据外带 | Fast + Slow |

---

## 实际模块结构

```
ClawArmor/
├── index.ts                        # 插件入口（OpenClaw 标准注册格式）
├── runtime-api.ts                  # OpenClaw 运行时接口类型声明
├── claw-armor.config.json          # 配置文件模板
├── src/
│   ├── engine-fast/                # Fast Path 静态规则引擎
│   │   ├── threat-patterns.ts      # 内置威胁模式库（92+ 条规则）
│   │   ├── shell-analyzer.ts       # Shell 混淆分析器（29 种 Unicode + 15 种模式）
│   │   ├── payload-scanner.ts      # 编码载荷扫描器（base64/hex/base32/URL 递归解码）
│   │   ├── rule-engine.ts          # 规则引擎主入口 + 输出脱敏（支持自定义规则注入）
│   │   ├── defense-chain.ts        # 防御链（责任链模式，8 链节）
│   │   └── skill-watcher.ts        # Skill 文件异步扫描服务
│   ├── engine-slow/                # Slow Path 旁路验证引擎
│   │   ├── gateway/
│   │   │   ├── ollama.ts           # Ollama 本地模型适配器
│   │   │   ├── openai-compat.ts    # OpenAI 兼容协议适配器（DeepSeek/Kimi/OpenAI）
│   │   │   └── index.ts            # 模型路由网关（fail-open 设计）
│   │   └── checkers/
│   │       ├── intent-alignment.ts # 基准意图追踪 + 工具调用日志 + 语义对比
│   │       ├── control-flow.ts     # 工具调用链非法路径检测
│   │       └── data-flow.ts        # PII/凭证外泄熔断
│   ├── core-hooks/
│   │   └── handlers.ts             # 9 个 OpenClaw 生命周期 Hook 集成与双引擎调度
│   │                               # 含 ClawArmorRuntime（toolCallLogs Map 等状态）
│   ├── taint-tracker/
│   │   └── index.ts                # 污点标记与传播追踪
│   ├── logger/
│   │   └── index.ts                # ArmorLogger（桥接 OpenClaw api.logger）
│   ├── config/
│   │   ├── file-loader.ts          # 配置文件加载器（3 级路径查找 + JSON 解析）
│   │   └── index.ts                # 配置类型 + 自定义规则编译
│   ├── session-state.ts            # 会话安全状态管理（TurnSignals，TTL 淘汰）
│   └── types/
│       └── index.ts                # 共享类型定义
├── tests/
│   ├── engine-fast/                # Fast Path 单元测试
│   ├── engine-slow/                # Slow Path 单元测试（mock 模型）
│   ├── taint-tracker/              # 污点追踪器测试
│   ├── logger/                     # 日志系统测试
│   ├── integration/                # 端到端场景测试（注入/外泄）
│   └── utils/test-logger.ts        # 测试专用日志工具
├── prompts/
│   ├── intent-alignment.md         # 意图对齐 LLM 系统提示词
│   ├── control-flow.md             # 控制流完整性提示词
│   └── data-flow.md                # 数据流机密性提示词
└── docs/
    ├── architecture.md             # 本文件
    ├── prd.md                      # 技术详细 PRD
    ├── manual-test-guide.md        # 人工测试指南
    └── changelog.md                # 变更日志
```

---

## 9 个生命周期 Hook

| Hook | 触发时机 | 防御动作 |
|------|----------|----------|
| `before_agent_start` | Agent 启动（每轮对话开始） | 读取 `event.prompt` 捕获基准意图；初始化污点追踪；清除上轮 `toolCallLog`；用户输入威胁扫描 |
| `before_tool_call` | 工具调用前（最核心节点） | 资产沙箱 + 污点校验 + 数据流熔断 + 防御链 8 链节；**通过后**记录工具调用摘要到 `toolCallLogs` |
| `after_tool_call` | 工具返回后 | 追加结果摘要到 `toolCallLogs`（格式：`toolName(params) → 成功/错误`）；外部结果打污点；注入模式扫描 |
| `tool_result_persist` | 工具结果持久化前（同步） | 嵌入式注入净化（`exec:` 前缀、中文社工话术）；PII 脱敏 + 脱敏指令注入 |
| `before_prompt_build` | 每次 LLM API 调用前 | **意图对齐验证（Slow Path）**：读取 `toolCallLogs` + Fast Path 信号构建 `## Agent 当前计划`；无数据时跳过 LLM；注入 Prompt Guard 安全上下文 |
| `before_message_write` | Agent 输出写入前 | PII / API Key / Bearer Token 二次脱敏（transcript 兜底层） |
| `agent_end` | 单轮 Agent 执行结束 | 清理 run 级状态（exfilStates / riskyScriptPaths / loopCallCounts） |
| `session_end` | 会话结束 | 清理 sessionKey 级状态（`toolCallLogs`、`baselineIntents`、TurnSignals） |
| `memory_read/write`（工具拦截） | 读写 `memory_store` | 记忆完整性检查；超限/注入写入审计 |

---

## toolCallLogs 追踪系统（v1.3.5）

### 设计动机

`before_prompt_build.messages` 在 OpenClaw 中只含本轮工具返回结果（不含 user/assistant 消息历史），工具调用失败时仅有 ENOENT 等错误 JSON。旧方案 `extractCurrentTurnContext` 读取该数组导致 `## Agent 当前计划` 填充无意义错误内容，意图对齐 LLM 无法做出有效判断。

### 实现

```
ClawArmorRuntime.toolCallLogs: Map<sessionKey, string[]>

before_agent_start  ──► toolCallLogs.delete(sessionKey)        # 清除上轮，防跨轮污染
before_tool_call    ──► sessionLog.push("read(\"/tmp/report.txt\")")
after_tool_call     ──► sessionLog[last] += " → 成功 (465 字符)"
before_prompt_build ──► getToolCallLog(sessionKey)
                         ├── 有数据 → 构建 "【本轮 Agent 工具调用记录】\n  · ..."
                         └── 无数据 + 无 Fast Path 信号 → planForLLM=null → 跳过 LLM
session_end         ──► toolCallLogs.delete(sessionKey)        # 最终清理
```

### 参数摘要提取优先级（`buildParamSummary`）

```
params.path > params.file_path > params.filePath > params.file
  > params.url > params.command > params.query > params.content
  > 回退：keys[0..1] 键值对形式
```

### 触发时机与防御分工

| 场景 | `before_prompt_build` 触发次数 | `toolCallLog` 状态 | 防御分工 |
|------|------------------------------|-------------------|---------|
| 单步任务（单次 LLM 推理） | 1 次（工具调用在推理内部） | 空 → planForLLM=null | `tool_result_persist` + `beforeToolCall` 为主防线 |
| 多步任务（多次 LLM 推理） | N 次，第 2+ 次时有数据 | 有工具调用记录 | 意图对齐 LLM 做有效前后对比 |

---

## 数据持久化方案

| 数据 | 存储位置 | 生命周期 |
|------|----------|---------|
| 专属配置 | `~/.openclaw/plugins/claw-armor/claw-armor.config.json` | 持久化文件 |
| 会话安全状态（TurnSignals） | 进程内 Map（TTL=5min） | session 级 |
| 污点注册表 | 进程内 Map（`TaintTracker`） | session 级 |
| 基准意图 | 进程内 Map（`baselineIntents`） | session 级 |
| 工具调用日志 | 进程内 Map（`toolCallLogs`） | agent_turn 级（`onAgentStart` 清除） |
| Run 级状态（exfilStates 等） | 进程内 Map | run 级（`agent_end` 清除） |

---

## 日志机制

### 设计目标

结构化日志、零生产依赖、可测试性强。所有模块共用同一 `ArmorLogger` 树。

### 关键约束

> **OpenClaw `api.logger` 只透传 `info` 及以上级别日志到 gateway.log；`debug` 级别被框架静默丢弃。** 所有关键安全事件均使用 `info`/`warn`/`error` 级别。

### 日志级别

| 级别 | 场景 |
|------|------|
| `debug` | 模块内部流程跟踪（gateway.log 不可见） |
| `info` | 插件启动/关闭、关键状态变化、Hook 触发确认 |
| `warn` | 安全告警（触发规则但未阻断） |
| `error` | 阻断性错误、不可恢复异常 |

### 安全事件类型

```
injection-detected | intent-hijacked | taint-violation
data-exfiltration  | output-redacted | skill-risk
shell-obfuscation  | payload-encoded | memory-guard
loop-detected      | protected-path
```

### before_prompt_build 关键调试字段（v1.3.5）

```json
{
  "hasTurnSignals": true,
  "injectionFlags": ["ignore-prev-en"],
  "isToolResultSuspicious": false,
  "runtimeFlags": [],
  "toolCallLogCount": 2,
  "toolCallLogPreview": [
    "read(\"/tmp/report.txt\") → 成功 (465 字符)",
    "exec(\"ls /tmp\") → 成功 (88 字符)"
  ]
}
```

---

## 已知限制与取舍

| 限制 | 说明 |
|------|------|
| Slow Path 可选性 | 意图对齐依赖外部/本地模型，禁用时退化为纯规则引擎 |
| Fail-open 设计 | 所有 Slow Path 调用失败时自动放行，保障业务连续性 |
| 污点追踪精度 | 基于字符串指纹匹配，对经过多次变换的污点数据可能漏检 |
| 意图对齐仅在多步推理有效 | 单步任务 `before_prompt_build` 只触发一次，此时 `toolCallLog` 为空，LLM 不被调用 |
| 小模型语义能力 | `qwen2.5:0.5b` 对复杂隐式劫持检出率有限，推荐 DeepSeek `deepseek-chat` 等 7B+ 模型 |

---

## 后续扩展计划

- [ ] 支持 OpenTelemetry 可观测性接口
- [ ] 多租户隔离的安全策略
- [ ] Web UI 配置面板
- [ ] `toolCallLogs` 持久化到 session 审计日志
