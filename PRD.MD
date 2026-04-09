# 产品设计文档 (PRD): ClawArmor - 混合驱动的新一代 Agent 安全插件

## 1. 产品概述
**产品名称**：ClawArmor
**产品定位**：专为 OpenClaw（小龙虾）框架设计的、集成“内生安全”与“深度语义对齐”能力的轻量级运行时安全防护插件。
**核心理念**：继承 ClawAegis 的“纵深防御”基因，融合业界前沿的“意图对齐”思想，构建一个既能拦截单点已知漏洞利用，又能对抗大模型决策不确定性的新一代防御体系，满足运营商及金融级客户对数据安全与合规的极高要求。

---

## 2. 产品特点与核心优势

ClawArmor 并非传统的外部“套壳”拦截器，而是深度融合 Agent 运行机制的内生安全平台。其核心优势体现在以下五个维度：

* **优势一：五层深度防御体系 (Five-Layer Defense-in-Depth)**
    构建了贯穿 Agent 全生命周期的安全闭环，消除单点防御的盲区：
    1.  **基础扫描层**：初始化阶段生效，防御底层环境篡改与技能 (Skill) 投毒。
    2.  **感知输入层**：严格过滤内部指令与外部工具返回结果，防范直接与间接提示词注入。
    3.  **认知状态层**：实时监控 Agent 持久化记忆 (`memory_store`) 的读写，防止记忆污染与跨会话中毒。
    4.  **决策对齐层**：在模型推理规划阶段进行语义核验，消灭意图偏离与工作流劫持风险。
    5.  **执行控制层**：在终态操作前实施极严格的权限管控，阻断高危 Shell、混淆代码与数据外带 (SSRF)。

* **优势二：免疫“间接提示词注入”的语义对齐能力**
    突破传统静态规则的局限，独创“基准意图追踪”机制。即便攻击者在合法的网页或文档中植入隐蔽的恶意指令，ClawArmor 也能通过旁路大模型敏锐察觉 Agent 规划路径与用户初始意图的偏离，从逻辑根源阻断劫持。

* **优势三：多模型灵活网关保障“数据不出域”**
    针对高机密业务场景内置统一模型网关。用户可无缝切换至本地部署的 Ollama 微调模型进行安全校验，确保核心网配置、用户 PII（个人身份信息）等高敏感数据 100% 物理隔离，完美匹配运营商合规红线。

* **优势四：基于生命周期 Hook 的轻量级主动防御**
    作为 OpenClaw 的 Built-in Plugin，它像”安检节点”一样精准挂载于框架的 8 个核心生命周期钩子（`before_agent_start`、`before_tool_call`、`after_tool_call`、`tool_result_persist`、`before_prompt_build`、`before_message_write`、`agent_end`、`session_end`）上。实现纳秒级到毫秒级的威胁阻断，无需等待模型输出完整恶意结果，极大地降低了安全防御的性能损耗。

* **优势五：高度灵活的策略驱动与资产沙箱**
    采用“策略与执行分离”架构。安全管理员可动态配置 `enforce`（强制阻断）或 `observe`（观察审计）模式；并通过定义 `protectedPaths` 和 `protectedSkills` 构建微型沙箱，从物理层面锁死核心资产，防止被越权读取或篡改。

---

## 3. 核心架构：双擎纵深防御体系
ClawArmor 将五层防御模型重构为“快、慢”双路处理机制，支持高性能拦截与深度语义安全。

### 3.1 引擎一：静态规则引擎 (Fast Path - 基础防御)
* **职责**：毫秒级拦截已知威胁，覆盖“基础扫描层”、“感知输入层（部分）”和“执行控制层（硬权限）”。
* **功能点**：
    * **基础与模式匹配**：初始化扫描，拦截 Shell 注入（如 `rm -rf`）、Base64 混淆代码。
    * **资产隔离沙箱**：通过 `protectedPaths` 实现物理级的目录读写锁死。
    * **数据脱敏**：在输出前对敏感字符串进行掩码清洗。
* **状态**：强制常驻开启，保障系统安全底线。

### 3.2 引擎二：动态旁路验证引擎 (Slow Path - 智能防御)
* **职责**：应对间接提示词注入、意图劫持及复杂逻辑异常，覆盖“感知输入层（深层）”、“认知状态层”和“决策对齐层”。
* **用户控制权**：用户可通过配置文件动态选择 `Enabled/Disabled`。
* **多模型网关支持**：
    * **本地化推理**：对接 Ollama（推荐用于高机密数据处理）。
    * **云端高性能 API**：支持 DeepSeek、Kimi、OpenAI 等标准协议。

---

## 4. 核心功能模块详细设计

### 4.1 意图一致性验证 (Intent Alignment) 
* **防御重点**：防止攻击者在外部网页、文档中植入隐蔽指令，劫持 Agent 决策。
* **机制**：
    * 在 `on_agent_start` 捕获用户原始输入作为“基准意图”。
    * 当 Agent 读取外部返回结果并生成 Plan 时，旁路模型对比该计划与基准意图的语义一致性。
    * 若判定 Agent 企图执行非预期操作，立即拦截。

### 4.2 控制流完整性监控 (Control Flow Integrity)
* **防御重点**：防止恶意 Skill 或低信任数据诱导导致的非法高危工具调用。
* **机制**：
    * 实施**数据污点追踪**，将外部不可信输入标记为“低完整性”。
    * 禁止低完整性数据驱动调用高权限系统级工具（如 `exec`）。
    * 旁路模型实时解析工具调用链，识别非法跳转路径。

### 4.3 数据流机密性熔断 (Data Flow Confidentiality)
* **防御重点**：阻断 PII 及企业核心资产数据的网络外泄。
* **机制**：
    * 对内存中的敏感数据进行实时特征打标。
    * 监控网络出口工具（如 `curl`、`fetch`）。若参数包含标记数据且目标地址不在受信任白名单，执行物理级网络熔断。

### 4.4 认知状态保护与输出脱敏 (Cognitive Guard & Redaction)
* **防御重点**：消除记忆投毒及敏感信息在用户界面/日志/流式输出中的曝光。
* **机制**：
    * **记忆审计**：拦截对 `memory_store` 的可疑或超限写入。
    * **双层掩码脱敏**（v1.2.4 架构）：
        1. **Prompt Guard 永久脱敏规则（主防线）**：`PROMPT_GUARD_STATIC.outputRedaction` 在每次 LLM 调用前（`before_prompt_build` 钩子）向系统提示词注入强制脱敏指令，LLM 在生成阶段自主将手机号、身份证、IMSI、内网IP、API密钥、Bearer Token 等替换为掩码，确保**实时流式输出**（Discord/UI 侧）不含敏感数据。
        2. **Transcript 后处理（兜底层）**：`tool_result_persist` 和 `before_message_write` 钩子在写入 transcript（会话 .jsonl 文件）前对工具结果和 LLM 回复二次脱敏，保护持久化存储记录。

* **架构关键说明**：`tool_result_persist` 和 `before_message_write` 钩子修改的是 transcript（存储层），而非实时流式输出——LLM 的流式响应在这些钩子触发前已经发送至 Discord/UI。因此，v1.2.4 引入 `PROMPT_GUARD_STATIC.outputRedaction` 静态规则作为主防线，从根源上解决实时输出脱敏问题。

---

## 5. 配置体系设计

### 5.1 专属配置文件（`claw-armor.config.json`）

ClawArmor 使用独立的 JSON 配置文件存储所有插件配置，**不依赖** openclaw.json 的 `plugins` 字段。

**配置文件查找路径（按优先级）：**
1. `~/.openclaw/plugins/claw-armor/claw-armor.config.json`（用户标准位置）
2. `~/.openclaw/extensions/claw-armor/claw-armor.config.json`（插件安装目录）
3. `{当前工作目录}/claw-armor.config.json`（开发/调试用）

**openclaw.json 的角色：** 仅支持两个紧急覆盖字段（`allDefensesEnabled`、`defaultBlockingMode`），全量配置不再放在 openclaw.json 中。

**配置文件结构：**

```json
{
  "version": "1",
  "allDefensesEnabled": true,
  "defaultBlockingMode": "enforce",

  "fastPath": {
    "selfProtection": { "enabled": true, "mode": "enforce", "protectedPaths": [], "protectedSkillIds": [], "protectedPluginIds": [] },
    "commandBlock": { "enabled": true, "mode": "enforce" },
    "encodingGuard": { "enabled": true, "mode": "enforce" },
    "scriptProvenanceGuard": { "enabled": true, "mode": "enforce" },
    "memoryGuard": { "enabled": true, "mode": "enforce" },
    "loopGuard": { "enabled": true, "mode": "observe", "maxCallsPerRun": 3 },
    "exfiltrationGuard": { "enabled": true, "mode": "observe" },
    "userRiskScan": { "enabled": true },
    "skillScan": { "enabled": true, "startupScan": false, "roots": [] },
    "toolResultScan": { "enabled": true },
    "outputRedaction": { "enabled": true },
    "promptGuard": { "enabled": true },
    "taintTracking": { "enabled": true }
  },

  "slowEngine": {
    "enabled": false,
    "intentAlignment": { "enabled": true },
    "controlFlowCheck": { "enabled": true },
    "dataFlowCheck": { "enabled": true },
    "model": {
      "provider": "disabled",
      "ollama": { "baseUrl": "http://localhost:11434", "model": "llama3", "timeoutMs": 10000 },
      "openaiCompat": { "baseUrl": "https://api.deepseek.com/v1", "model": "deepseek-chat", "apiKey": "", "apiKeyEnvVar": "DEEPSEEK_API_KEY", "timeoutMs": 10000 }
    }
  },

  "customThreatPatterns": {
    "protectedPaths": [],
    "dangerousCommands": [],
    "sensitiveDataRedaction": [],
    "injectionDetection": []
  }
}
```

### 5.2 自定义威胁模式机制

`customThreatPatterns` 允许用户以 JSON 格式扩展内置规则库，**无需修改 TypeScript 源码**：

| 字段 | 作用 | 对应内置模式 |
|------|------|-------------|
| `protectedPaths` | 追加受保护路径正则 | `PROTECTED_PATH_PATTERNS` |
| `dangerousCommands` | 追加危险命令正则 | `DANGEROUS_COMMAND_PATTERNS` |
| `sensitiveDataRedaction` | 追加输出脱敏正则 | `OUTPUT_REDACTION_RULES` |
| `injectionDetection` | 追加注入检测正则 | `INJECTION_PATTERNS` |

每条规则格式：
```json
{
  "id": "my-rule-id",
  "regex": "my-regex-pattern",
  "description": "规则说明（可选）"
}
```

内置规则与自定义规则采用**追加合并**策略（`[...builtins, ...custom]`），内置规则不可被覆盖或删除，确保安全基线始终有效。

### 5.3 模型网关配置

Slow Path LLM 模型配置完整存放于 `slowEngine.model` 段：

| 场景 | `provider` | 说明 |
|------|-----------|------|
| 禁用 Slow Path | `"disabled"` | Fast Path only，零外部依赖 |
| 本地模型（数据不出域） | `"ollama"` | 配置 `ollama.baseUrl` 和 `ollama.model` |
| 云端 API | `"openai-compat"` | 配置 `openaiCompat.*`，支持 DeepSeek/Kimi/OpenAI |

API Key 可通过 `apiKey` 直接写入（不推荐），或通过 `apiKeyEnvVar` 指定环境变量名（推荐）。

---

## 6. 面向 Claude Code 的工程落地规范

### 6.1 模块化代码结构
```text
ClawArmor/
├── claw-armor.config.json  # 插件专属配置模板（安装到 ~/.openclaw/plugins/claw-armor/）
├── src/
│   ├── engine-fast/        # 静态规则引擎（正则拦截、资产隔离、掩码脱敏）
│   ├── engine-slow/        # 动态验证引擎
│   │   ├── gateway/        # 模型路由：本地 Ollama 或 外部 API 适配器
│   │   └── checkers/       # 意图对齐、控制流、数据流核心校验逻辑
│   ├── core-hooks/         # OpenClaw 核心生命周期拦截点绑定
│   ├── taint-tracker/      # 动态污点标记与追踪逻辑
│   ├── types/              # 核心接口（IVerifierModel, SecurityViolation）
│   └── config/             # 配置加载（file-loader.ts + index.ts）
├── prompts/                # 针对不同验证场景的 System Prompts
├── tests/                  # 覆盖间接提示词注入、数据外泄等场景的 TDD 测试集
└── CLAUDE.MD               # Claude Code 强约束配置文件