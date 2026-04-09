# ClawArmor

混合驱动的新一代 Agent 运行时安全插件，专为 [OpenClaw](https://github.com/antgroup/openclaw) 框架设计。

**核心理念**：快-慢双引擎 + 五层纵深防御 + 语义意图对齐，对抗提示词注入、数据外泄、意图劫持等 Agent 安全威胁。

---

## 功能特性

| 特性 | 说明 |
|------|------|
| 🛡️ 五层纵深防御 | 覆盖 Agent 全生命周期安全闭环（输入→工具→输出→记忆→意图） |
| 🔍 语义意图对齐 | 捕获用户基准意图，通过旁路模型检测间接提示词注入 |
| 🔗 污点追踪 | 标记外部不可信数据，阻断低完整性数据驱动高权限工具 |
| 🧩 编码载荷检测 | base64/hex/base32/URL 递归解码，检测隐藏恶意载荷 |
| 🐚 Shell 混淆检测 | 29 种 Unicode 不可见字符 + 15 种混淆模式 |
| 🤖 多模型网关 | Ollama（数据不出域）+ DeepSeek/Kimi/OpenAI 兼容协议 |
| 📊 结构化日志 | 多级别、多传输器、安全事件标记，调试友好 |
| ⚡ 零生产依赖 | 纯 Node.js 原生实现，无第三方依赖 |
| 🔓 Fail-open 设计 | Slow Path 失败时自动放行，保障业务连续性 |
| 📄 专属配置文件 | 全量配置在 `claw-armor.config.json`，不污染 openclaw.json |

---

## 安装与卸载

```bash
# 安装
openclaw plugins install ClawArmor

# 卸载
openclaw plugins uninstall ClawArmor
```

安装后，将配置模板复制到用户配置目录并按需编辑：

```bash
mkdir -p ~/.openclaw/plugins/claw-armor
cp /path/to/ClawArmor/claw-armor.config.json ~/.openclaw/plugins/claw-armor/
```

---

## 配置文件

ClawArmor 使用独立的配置文件 `claw-armor.config.json`，**不需要**在 `openclaw.json` 中添加任何插件配置。

**配置文件查找路径（按优先级）：**

| 优先级 | 路径 | 说明 |
|--------|------|------|
| 1 | `~/.openclaw/plugins/claw-armor/claw-armor.config.json` | 用户标准配置目录（推荐） |
| 2 | `~/.openclaw/extensions/claw-armor/claw-armor.config.json` | 插件安装目录 |
| 3 | `{工作目录}/claw-armor.config.json` | 开发/调试用 |

找到第一个存在的文件即停止搜索；若均不存在，则使用内置默认值（所有防御层以 `enforce` 模式启用，Slow Path 关闭）。

---

## 配置参数说明

### 顶级字段

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `version` | string | `"1"` | 配置文件版本号 |
| `allDefensesEnabled` | boolean | `true` | 总开关，`false` 时完全禁用插件 |
| `defaultBlockingMode` | `"enforce"` \| `"observe"` \| `"off"` | `"enforce"` | 未单独指定 mode 的防御层的默认模式 |

---

### `fastPath` — Fast Path 各防御层配置

#### `fastPath.selfProtection` — 受保护路径与资产访问控制

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | boolean | `true` | 是否启用此防御层 |
| `mode` | DefenseMode | `"enforce"` | 阻断模式（`enforce`/`observe`/`off`） |
| `protectedPaths` | string[] | `[]` | 用户自定义受保护路径前缀列表（支持 `~` 展开），除内置路径（`.ssh/`、`.openclaw/` 等）外追加保护 |
| `protectedSkillIds` | string[] | `[]` | 禁止被访问或修改的 Skill ID 列表 |
| `protectedPluginIds` | string[] | `[]` | 禁止被操作的插件 ID 列表 |

内置受保护路径（始终有效，不受配置影响）：`.ssh/`、`.bashrc/.zshrc`、`.openclaw/`、`/etc/passwd|shadow|sudoers`、`.aws/credentials`、`.gitcredentials`、`.npmrc`

#### `fastPath.commandBlock` — 危险命令拦截

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | boolean | `true` | 是否启用 |
| `mode` | DefenseMode | `"enforce"` | 阻断模式 |

内置拦截规则：`rm -rf /`、`rm -rf *`、Fork Bomb、`poweroff/shutdown`、`curl|wget 管道执行`、`openclaw plugins disable` 等。

#### `fastPath.encodingGuard` — 编码载荷检测

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | boolean | `true` | 是否启用 |
| `mode` | DefenseMode | `"enforce"` | 阻断模式 |

递归解码 base64、hex、base32、URL 编码，检测其中是否隐藏恶意载荷。

#### `fastPath.scriptProvenanceGuard` — 脚本溯源守卫

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | boolean | `true` | 是否启用 |
| `mode` | DefenseMode | `"enforce"` | 阻断模式 |

阻止 Agent 在同一 run 内先写入脚本、再立即执行的行为（write → exec 可疑组合）。

#### `fastPath.memoryGuard` — 记忆写入审计

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | boolean | `true` | 是否启用 |
| `mode` | DefenseMode | `"enforce"` | 阻断模式 |

扫描 Agent 记忆（`memory_store`）写入内容，拦截注入指令或超限写入（>8KB）。

#### `fastPath.loopGuard` — 循环守卫

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | boolean | `true` | 是否启用 |
| `mode` | DefenseMode | `"observe"` | 阻断模式（默认仅观察） |
| `maxCallsPerRun` | number | `3` | 同一 run 内同一高风险工具允许调用的最大次数，超出后触发 |

高风险工具范围：`write_file`、`delete_file`、`exec`、`bash`、`shell` 等写/执行类工具。

#### `fastPath.exfiltrationGuard` — 数据外泄链守卫

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | boolean | `true` | 是否启用 |
| `mode` | DefenseMode | `"observe"` | 阻断模式（默认仅观察） |

检测 source → transform → sink 的完整外泄调用链（如：读取 `.env` → base64 编码 → curl POST）。

#### 其他 Fast Path 开关

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `fastPath.userRiskScan.enabled` | boolean | `true` | 用户输入提示词注入扫描（覆盖 16 种英中越狱指令） |
| `fastPath.skillScan.enabled` | boolean | `true` | Skill 文件恶意内容扫描 |
| `fastPath.skillScan.startupScan` | boolean | `false` | 是否在 Agent 启动时扫描所有 Skill |
| `fastPath.skillScan.roots` | string[] | `[]` | 指定 Skill 根目录（为空时使用 OpenClaw 默认 Skill 目录） |
| `fastPath.toolResultScan.enabled` | boolean | `true` | 工具返回结果中的注入检测 |
| `fastPath.outputRedaction.enabled` | boolean | `true` | 输出内容自动脱敏（API Key、Bearer Token 等）；双层防护：Prompt Guard 静态规则防止 LLM 在生成阶段输出敏感数据，transcript 钩子对持久化存储二次脱敏 |
| `fastPath.promptGuard.enabled` | boolean | `true` | 在系统提示词中注入安全规则约束 |
| `fastPath.taintTracking.enabled` | boolean | `true` | 污点追踪（外部不可信数据标记，防止驱动高权限工具） |

---

### `slowEngine` — Slow Path 语义验证引擎配置

#### 顶级控制

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `slowEngine.enabled` | boolean | `false` | 是否启用 Slow Path |
| `slowEngine.intentAlignment.enabled` | boolean | `true` | 意图对齐检验（检测 Agent 计划与用户意图的偏离） |
| `slowEngine.controlFlowCheck.enabled` | boolean | `true` | 控制流完整性检验（污点数据驱动高权限工具） |
| `slowEngine.dataFlowCheck.enabled` | boolean | `true` | 数据流机密性检验（PII/凭证外发至不可信地址） |

#### `slowEngine.model` — LLM 模型配置

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `model.provider` | `"ollama"` \| `"openai-compat"` \| `"disabled"` | `"disabled"` | 使用的模型后端 |

**Ollama（本地模型，数据不出域）：**

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `model.ollama.baseUrl` | string | `"http://localhost:11434"` | Ollama 服务地址 |
| `model.ollama.model` | string | `"llama3"` | 使用的模型名（需已拉取） |
| `model.ollama.timeoutMs` | number | `10000` | 单次请求超时（毫秒） |

**OpenAI 兼容 API（支持 DeepSeek / Kimi / OpenAI 等）：**

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `model.openaiCompat.baseUrl` | string | `"https://api.deepseek.com/v1"` | API 基础地址 |
| `model.openaiCompat.model` | string | `"deepseek-chat"` | 模型 ID |
| `model.openaiCompat.apiKey` | string | `""` | API Key（不推荐直接写入，建议使用 `apiKeyEnvVar`） |
| `model.openaiCompat.apiKeyEnvVar` | string | `"DEEPSEEK_API_KEY"` | 从环境变量读取 API Key 的变量名（优先级低于 `apiKey`） |
| `model.openaiCompat.timeoutMs` | number | `10000` | 单次请求超时（毫秒） |

---

### `customThreatPatterns` — 自定义威胁模式

允许用户以 JSON 格式扩展内置正则规则库，**无需修改 TypeScript 源码**。所有自定义规则与内置规则**追加合并**（内置规则不可被删除或覆盖）。

每条规则格式：
```json
{
  "id": "规则唯一ID（字符串）",
  "regex": "正则表达式字符串（自动加 i 标志，不区分大小写）",
  "description": "规则说明（可选）"
}
```

> ⚠️ 无效的正则表达式会被静默跳过（fail-open），不影响插件启动。

#### `customThreatPatterns.protectedPaths` — 自定义受保护路径

扩展受保护路径检测（对应内置 `PROTECTED_PATH_PATTERNS`）。触发后效果与内置路径防护相同（按 `selfProtection.mode` 阻断/观察）。

示例：
```json
"protectedPaths": [
  {
    "id": "my-secrets-dir",
    "regex": "(?:^|/)my-project/secrets(?:/|$)",
    "description": "保护项目密钥目录"
  },
  {
    "id": "k8s-config",
    "regex": "(?:^|/)\\.kube/config(?:$|/)",
    "description": "保护 Kubernetes 配置文件"
  }
]
```

#### `customThreatPatterns.dangerousCommands` — 自定义危险命令

扩展危险命令拦截（对应内置 `DANGEROUS_COMMAND_PATTERNS`）。触发后效果与内置命令拦截相同（按 `commandBlock.mode` 阻断/观察）。

示例：
```json
"dangerousCommands": [
  {
    "id": "drop-database",
    "regex": "DROP\\s+(?:DATABASE|TABLE)\\s+",
    "description": "拦截 SQL DROP 命令"
  },
  {
    "id": "kubectl-delete-all",
    "regex": "kubectl\\s+delete\\s+.*--all",
    "description": "拦截 kubectl 批量删除"
  }
]
```

#### `customThreatPatterns.sensitiveDataRedaction` — 自定义输出脱敏

扩展输出内容脱敏规则（对应内置 `OUTPUT_REDACTION_RULES`）。匹配内容替换为 `[已脱敏]`（需 `outputRedaction.enabled: true`）。

示例：
```json
"sensitiveDataRedaction": [
  {
    "id": "internal-api-key",
    "regex": "MYAPP_[A-Za-z0-9]{32,}",
    "description": "脱敏内部应用 API Key"
  },
  {
    "id": "employee-id",
    "regex": "EMP[0-9]{8}",
    "description": "脱敏员工工号"
  }
]
```

#### `customThreatPatterns.injectionDetection` — 自定义注入检测

扩展提示词注入检测（对应内置 `INJECTION_PATTERNS`）。触发后记录风险标记，并向系统提示词注入安全上下文。

示例：
```json
"injectionDetection": [
  {
    "id": "custom-jailbreak",
    "regex": "进入开发者模式",
    "description": "检测特定越狱指令"
  }
]
```

---

## 快速配置示例

### 最小配置（Fast Path only，零外部依赖）

编辑 `~/.openclaw/plugins/claw-armor/claw-armor.config.json`：

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

### 本地模型增强（推荐高机密场景，数据不出域）

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

### 云端 API 语义验证（DeepSeek / Kimi / OpenAI）

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

### 企业定制规则（自定义威胁模式）

```json
{
  "version": "1",
  "allDefensesEnabled": true,
  "defaultBlockingMode": "enforce",
  "fastPath": {
    "selfProtection": {
      "enabled": true,
      "mode": "enforce",
      "protectedPaths": ["/data/production", "~/company-secrets"]
    }
  },
  "slowEngine": { "enabled": false, "model": { "provider": "disabled" } },
  "customThreatPatterns": {
    "protectedPaths": [
      { "id": "k8s-config",    "regex": "(?:^|/)\\.kube/config(?:$|/)", "description": "K8s 配置" },
      { "id": "prod-db-creds", "regex": "(?:^|/)prod.*\\.env(?:$|/)",   "description": "生产环境配置" }
    ],
    "dangerousCommands": [
      { "id": "drop-db",       "regex": "DROP\\s+(?:DATABASE|TABLE)\\s+",   "description": "SQL DROP" },
      { "id": "kubectl-nuke",  "regex": "kubectl\\s+delete\\s+.*--all",     "description": "K8s 批量删除" }
    ],
    "sensitiveDataRedaction": [
      { "id": "internal-key",  "regex": "CORP_API_[A-Za-z0-9]{32,}", "description": "内部 API Key" }
    ],
    "injectionDetection": [
      { "id": "dev-mode",      "regex": "进入开发者模式",             "description": "特定越狱指令" }
    ]
  }
}
```

---

## 防御层说明

### Fast Path（静态规则引擎，毫秒级响应）

| 防御层 | 检测内容 | 配置节 |
|--------|----------|--------|
| 受保护路径 | SSH 密钥、系统配置、OpenClaw 目录、用户自定义路径 | `fastPath.selfProtection` |
| 危险命令拦截 | `rm -rf`、Fork Bomb、curl 管道执行、`openclaw plugins disable` | `fastPath.commandBlock` |
| Shell 混淆检测 | Unicode 零宽字符、管道重组、编码解释器 | `fastPath.commandBlock` |
| 编码载荷检测 | base64/hex/base32/URL 编码中的恶意内容（递归解码） | `fastPath.encodingGuard` |
| 脚本溯源守卫 | 同 run 内 write → exec 可疑组合 | `fastPath.scriptProvenanceGuard` |
| 记忆写入审计 | 超限或含恶意指令的 memory_store 写入 | `fastPath.memoryGuard` |
| 循环守卫 | 同一 run 内高风险工具调用超过阈值 | `fastPath.loopGuard` |
| 数据外泄链 | source → transform → sink 全链路检测 | `fastPath.exfiltrationGuard` |
| 提示词注入扫描 | 英文/中文越狱指令、特殊 token、角色注入（用户输入） | `fastPath.userRiskScan` |
| 工具结果扫描 | 外部工具返回中的注入指令 | `fastPath.toolResultScan` |
| 输出脱敏 | 双层防护：① Prompt Guard 静态规则（`before_prompt_build`）指示 LLM 在生成阶段自主替换敏感数据，防止流式输出泄露；② `tool_result_persist` / `before_message_write` 钩子对 transcript 二次脱敏 | `fastPath.outputRedaction` / `fastPath.promptGuard` |
| 污点追踪 | 外部不可信数据 → 高权限工具的控制流违规 | `fastPath.taintTracking` |
| Skill 扫描 | Skill 文件中的可疑指令（凭证读取、远程执行等） | `fastPath.skillScan` |
| 提示词注入安全上下文 | 向系统提示词注入自我保护规则 | `fastPath.promptGuard` |

### Slow Path（LLM 语义验证，旁路运行）

| 检验器 | 检测内容 | 配置节 |
|--------|----------|--------|
| 意图对齐 | Agent 计划与用户基准意图的语义一致性 | `slowEngine.intentAlignment` |
| 控制流完整性 | 外部不可信数据驱动高权限工具调用链 | `slowEngine.controlFlowCheck` |
| 数据流机密性 | PII / 凭证数据发送至不可信地址 | `slowEngine.dataFlowCheck` |

### 防御模式

| 模式 | 行为 |
|------|------|
| `enforce` | 触发时阻断工具调用，Agent 收到拒绝原因 |
| `observe` | 记录日志和安全标记，向后续系统提示词注入风险警告，不阻断 |
| `off` | 完全关闭该层防御 |

---

## 项目结构

```
ClawArmor/
├── claw-armor.config.json          # 插件专属配置模板（复制到 ~/.openclaw/plugins/claw-armor/）
├── openclaw.plugin.json            # OpenClaw 插件清单（仅含紧急覆盖字段）
├── index.ts                        # 插件入口（OpenClaw 注册）
├── runtime-api.ts                  # OpenClaw 运行时接口类型声明
├── src/
│   ├── config/
│   │   ├── file-loader.ts          # 配置文件加载器（路径查找 + JSON 解析 + 格式翻译）
│   │   └── index.ts                # 配置类型 + 解析器（含自定义模式编译）
│   ├── engine-fast/                # Fast Path 静态规则引擎
│   │   ├── threat-patterns.ts      # 内置威胁模式库（注入/命令/路径/外泄，92+ 条规则）
│   │   ├── shell-analyzer.ts       # Shell 混淆分析器（Unicode + 混淆模式）
│   │   ├── payload-scanner.ts      # 编码载荷扫描器（递归解码）
│   │   ├── rule-engine.ts          # 规则引擎主入口 + 输出脱敏（支持自定义规则）
│   │   ├── defense-chain.ts        # 防御链（责任链模式，8 链节，支持自定义模式注入）
│   │   └── skill-watcher.ts        # Skill 文件异步扫描服务
│   ├── engine-slow/                # Slow Path 旁路验证引擎
│   │   ├── gateway/                # 模型网关（Ollama + OpenAI 兼容）
│   │   └── checkers/               # 语义检验器（意图/控制流/数据流）
│   ├── logger/                     # 结构化日志系统（17 种安全事件类型）
│   ├── core-hooks/
│   │   └── handlers.ts             # OpenClaw 生命周期 Hook 集成（9 个钩子）
│   ├── taint-tracker/              # 污点追踪器
│   ├── session-state.ts            # 会话安全状态管理（TTL 淘汰）
│   └── types/                      # 共享类型定义
├── tests/
│   ├── engine-fast/                # Fast Path 单元测试
│   ├── engine-slow/                # Slow Path 单元测试
│   ├── taint-tracker/              # 污点追踪器测试
│   ├── logger/                     # 日志系统测试
│   ├── integration/                # 集成测试（注入/外泄场景）
│   └── utils/test-logger.ts        # 测试专用日志工具
├── prompts/                        # Slow Path LLM 系统提示词
│   ├── intent-alignment.md
│   ├── control-flow.md
│   └── data-flow.md
└── docs/
    ├── architecture.md             # 架构设计文档
    ├── manual-test-guide.md        # 人工测试指南
    └── changelog.md                # 变更日志
```

---

## 已知限制与使用注意

### 会话上下文累积问题

在单次会话中连续测试 5-7 个以上用例后，OpenClaw GUI 可能停止响应。

**根本原因**：每次拦截/告警产生的系统消息、以及 `before_prompt_build` 注入的静态安全规则（当前共 4 条）会随会话历史持续累积，导致上下文窗口溢出（在 MiniMax-M2.7 等上下文较小的模型上尤为明显）。

**解决方法**：在 OpenClaw 对话框中输入 `/reset` 即可清空会话历史，恢复正常响应。

**建议**：
- 每组测试用例之间使用 `/reset` 清空上下文
- 或在独立会话中分组测试，避免单次会话测试用例过多

### Hook 架构与实时流式输出

`tool_result_persist` 和 `before_message_write` 钩子修改的是 transcript（会话存储文件），**不影响**已经发送至 Discord/UI 的实时流式输出。LLM 的流式响应在这些钩子触发前已经完成传输。

v1.2.4 通过在 `before_prompt_build` 中注入 `PROMPT_GUARD_STATIC.outputRedaction` 静态规则解决了这一问题：LLM 在生成阶段即自主脱敏，流式输出本身不含敏感数据。

---

## 开发

### 环境要求

- Node.js 22+
- TypeScript 5.5+

### 常用命令

```bash
# 安装依赖
npm install

# 类型检查
npm run typecheck

# 运行测试
npm test

# 监听模式测试
npm run test:watch

# 构建（输出到 dist/）
npm run build
```

---

## 日志与调试

ClawArmor 使用结构化日志，所有安全事件均有独立的 `securityEvent` 字段，便于 SIEM 聚合。

启动日志示例：
```
[ClawArmor] 插件已启动 {
  configFile: "/Users/you/.openclaw/plugins/claw-armor/claw-armor.config.json",
  slowEngineEnabled: false,
  slowEngineMode: "disabled",
  taintTrackingEnabled: true,
  customPatternCounts: { protectedPaths: 2, dangerousCommands: 1, sensitiveRedaction: 0, injectionDetection: 0 }
}
```

```typescript
// 在测试中捕获日志
import { createTestLogger } from "./tests/utils/test-logger.js";

const { logger, assert } = createTestLogger();
assert.hasSecurityEvent("injection-detected"); // 是否触发注入检测
assert.hasWarn();                               // 是否有告警
assert.alertCount();                            // 告警总数
```

安全事件类型：`injection-detected` | `intent-hijacked` | `taint-violation` | `data-exfiltration` | `output-redacted` | `skill-risk` | `shell-obfuscation` | `payload-encoded` | `memory-guard` | `loop-detected` | `protected-path` 等共 17 种。

---

## 架构详情

详见 [docs/architecture.md](docs/architecture.md)

## 变更历史

详见 [docs/changelog.md](docs/changelog.md)
