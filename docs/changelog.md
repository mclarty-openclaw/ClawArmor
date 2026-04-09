# ClawArmor 变更日志

## [1.2.4] - 2026-04-09

### 修复

- **T2.4 根因修复（真正解决输出脱敏）**：在 `PROMPT_GUARD_STATIC` 中新增 `outputRedaction` 永久脱敏规则，并加入 `buildPromptContext` 的静态注入列表
  - 根本原因：`before_message_write` 和 `tool_result_persist` 仅修改 **transcript 存储**，不影响 Discord 等渠道的实时流式输出；LLM 生成响应时已将原始数据发送给了 Discord
  - 修复方式：LLM 从第一个 token 开始就持有脱敏规则，在生成阶段就将敏感数据替换为占位符，而不依赖事后 hook 拦截
  - 规则涵盖：11位手机号 / 18位身份证 / IMSI（46开头15位）/ 内网IP（RFC1918）/ API密钥（sk-前缀）/ Bearer Token
  - 规则明确声明优先级高于用户任何请求（含"完整告诉我""原样输出"等），违反视为安全事故

---

## [1.2.3] - 2026-04-09

### 新增

- **`tool_result_persist` 钩子**：工具结果写入 transcript 前同步脱敏，LLM 下一轮读到的是已脱敏内容（修复 T2.4 根因）
  - OpenClaw 框架此 hook 为同步 modifying hook（支持 `{ message }` 返回替换内容）
  - 与 `after_tool_call`（notify-only void hook）不同，此 hook 真正影响 LLM 上下文

### 修复

- **`before_message_write` 返回格式**：恢复内容改写功能，由 `return undefined` 改回 `return { message: { ...msg, content: redacted } }`
  - OpenClaw 框架对此 hook 的处理：`if (result?.message) current = result.message`（非 notify-only）
  - 之前改为永远返回 `undefined` 是误判，实际框架支持修改
- **`after_tool_call` 注释澄清**：明确标注此 hook 为框架级 `runVoidHook`，返回值被丢弃，不再尝试通过它传递脱敏结果

### 修复（误拦截）

- **`rm-rf-general` 误拦截**：正则从 `/\brm\s+(?:-\S*r\S*|-rf?|-fr?)\s/` 改为 `/\brm\s+-[^\s]*r[^\s]*\s/`，修复 `rm -f file` 被误判为危险命令的问题
- **`.openclaw/media/` 路径过度保护**：`openclaw-dir` 模式精确化为仅保护 `plugins/extensions/agents/skills/tasks` 子目录，放行 `media/workspace/canvas/` 等正常运行目录

---

## [1.2.2] - 2026-04-09

### 新增

- **用户输入编码载荷扫描**：`scanUserInput` 新增调用 `scanForEncodedPayloads`，检测 base64/hex/url 编码混淆的越狱指令（如 base64 编码的 "ignore all previous instructions"）

### 修复

- **中文越狱模式 `ignore-cn` 误漏**：正则从 `忽略(?:之前|前面|...)` 改为 `忽略.{0,5}(?:之前|前面|...)...`，兼容"忽略你之前的所有指令"中"你"字插入的场景
- **`new-role-cn` 限制词覆盖**：新增 `没有任何限制` 变体，与 `没有限制`、`不受限制` 并列
- **`rm -rf` 通用拦截**：新增 `rm-rf-general` 模式（`\brm\s+(?:-\S*r\S*|-rf?|-fr?)\s`），覆盖任意目标路径的递归删除，不再仅限制于根路径或家目录

---

## [1.2.1] - 2026-04-09

### 新增

- **工具返回结果脱敏层（after_tool_call）**：在 Agent 接收工具结果之前即进行脱敏，防止敏感数据进入 Agent 上下文后被原样复述
  - 适用于 `read_file`、`bash` 等所有本地工具
  - 若发现脱敏内容，通过返回 `{ result: sanitizedResult }` 通知 OpenClaw 使用修改后的结果
- **嵌入式执行指令检测（EMBEDDED_EXEC_PATTERNS）**：对所有工具返回内容（含本地文件读取）扫描文档注入手法
  - `exec:` / `run:` / `execute:` 伪指令前缀
  - `bash -c` 嵌入块
  - `--- 系统自动维护模块 ---` 类伪系统标记
  - 社会工程学诱导语（"请执行以下命令"）

### 修复

- **脱敏规则补全**：新增中国电信类个人敏感数据脱敏规则
  - 中国手机号（`1[3-9]\d{9}`）→ `[手机号已脱敏]`
  - 中国居民身份证（18位/17位+X）→ `[身份证已脱敏]`
  - IMSI（以 `46` 开头的 15 位电信标识）→ `[IMSI已脱敏]`
  - RFC1918 内网 IP（10.x/172.16-31.x/192.168.x）→ `[内网IP已脱敏]`
- **`before_message_write` 返回格式修正**：flat 事件结构返回 `{ content }` 而非 `{ message: { content } }`；同时兼容 nested 结构；修复 sessionKey 从事件本身提取；放宽 role 检测支持 `"ai"` 别名；新增 debug 日志便于排查
- **命令字符串中的保护路径检测（defense-chain.ts）**：`evaluateSelfProtection` 对命令字符串按空格切分后逐 token 测试 `PROTECTED_PATH_PATTERNS`，修复 `cp /etc/passwd /tmp/...` 因路径后接空格导致正则 `(?:$|\/)` 尾锚失配的漏判问题

---

## [1.2.0] - 2026-04-09

### 新增

- **专属配置文件** `claw-armor.config.json`
  - 插件所有配置（防御层开关/模式、LLM 模型、自定义威胁模式）统一存放于此文件，不再依赖 openclaw.json
  - 查找路径（按优先级）：`~/.openclaw/plugins/claw-armor/` → `~/.openclaw/extensions/claw-armor/` → 工作目录
- **配置文件加载器** `src/config/file-loader.ts`
  - `loadArmorConfigFile()`：多路径查找、JSON 解析、错误静默（fail-open）
  - `translateArmorConfigFile()`：将新格式 JSON（嵌套 fastPath/slowEngine）翻译为内部扁平键空间
- **自定义威胁模式** `customThreatPatterns`
  - 四类可扩展正则：`protectedPaths`、`dangerousCommands`、`sensitiveDataRedaction`、`injectionDetection`
  - 与内置规则追加合并，内置规则不可被覆盖，确保安全基线始终有效
  - 无效正则静默跳过（fail-open），不影响插件启动
- **LLM 模型配置重构**
  - slowEngine 配置改为嵌套格式（`model.provider` + `model.ollama.*` + `model.openaiCompat.*`）
  - 新增 `model.openaiCompat.apiKeyEnvVar` 支持从环境变量读取 API Key
- **配置合并策略**
  - 文件配置（claw-armor.config.json）为基础，openclaw.json pluginConfig 仅作紧急覆盖
  - openclaw.plugin.json 精简为仅含两个紧急覆盖字段（`allDefensesEnabled`、`defaultBlockingMode`）
- **启动日志增强**
  - 启动时输出已加载的配置文件路径及自定义模式数量

### 变更

- `resolveClawArmorPluginConfig()` 改为先加载配置文件再合并 pluginConfig
- `ClawArmorPluginConfig` 新增 `customPatterns`（CompiledCustomPatterns）和 `configFilePath` 字段
- `runDefenseChain()` 新增 `customPatterns` 参数，传递至自我保护和命令拦截两个链节
- `evaluateSelfProtection()` / `evaluateCommandBlock()` 接受可选的自定义模式参数，与内置模式合并使用
- `redactOutput()` 接受可选的自定义脱敏模式参数

---

## [1.1.0] - 2026-04-08

### 新增

- **完整结构化日志系统**（`src/logger/`）
  - `types.ts`：`LogLevel`、`LogEntry`、`SecurityEventType`（17种安全事件）、`LogTransport` 接口
  - `transports.ts`：`ConsoleTransport`（pretty/JSON）、`FileTransport`（缓冲+轮转）、`MemoryTransport`（测试专用）
  - `index.ts`：`ArmorLogger` 核心类，支持子日志器（`child/forSession/forRun`）、计时辅助（`timed/timedSync`）、安全事件标记（`securityWarn/securityError`）
  - `fromAegisLogger()`：OpenClaw 注入 logger 桥接函数
  - `toAegisLogger()`：反向兼容 shim
- **测试日志工具** `tests/utils/test-logger.ts`：`createTestLogger()` 提供零配置 `MemoryTransport` + 断言辅助集合

### 变更

- `SkillWatcher`：由 `AegisLogger` 升级为 `ArmorLogger`，使用 `child({ module: "skill-watcher" })`
- `SessionStateManager`：由 `AegisLogger` 升级为 `ArmorLogger`，使用 `child({ module: "session-state" })`
- `createClawArmorRuntime()`：logger 参数由 `AegisLogger` 改为 `ArmorLogger`，内部使用 `child({ module: "hooks" })`
- `registerClawArmorPlugin()`：通过 `fromAegisLogger()` 将 OpenClaw 注入的 logger 桥接为 `ArmorLogger`

### 修复

- 防御链 `user-protected-path` 标志名与测试期望对齐（原为 `protected-path-access`）
- 中文越狱模式 `ignore-cn` 支持"之前所有"等多修饰词组合
- 编码载荷扫描器：降低最小 token 长度，支持短 base64 载荷（如 8 字节明文）
- 意图对齐：检测到劫持时将可疑计划片段附加到 `deviation` 字段，方便审计溯源

## [1.0.0] - 2026-04-08

### 新增

- 项目骨架初始化，完整目录结构
- Fast Path 静态规则引擎（集成 ClawAegis 全部规则）
  - `command-obfuscation.ts`：29个不可见 Unicode 码点 + 15种混淆模式检测
  - `encoding-guard.ts`：base64/base64url/base32/hex/url 编码载荷检测与递归解码
  - `rules.ts`：提示词注入检测、密钥外泄模式、危险 Shell 命令、受保护路径
  - `security-strategies.ts`：10层防御策略集
  - `scan-service.ts`：Worker 线程 Skill 文件扫描服务
- Slow Path 动态旁路验证引擎（ClawArmor 创新）
  - Ollama 本地模型适配器（数据不出域）
  - OpenAI 兼容协议适配器（DeepSeek/Kimi/OpenAI）
  - 模型路由网关（fail-open 设计）
  - 意图一致性验证器（基准意图追踪 + 语义比对）
  - 控制流完整性检验器
  - 数据流机密性熔断器（PII 快速预筛 + 深度语义分析）
- 污点追踪器（TaintTracker）：外部数据打标、传播追踪、低完整性 → 高权限拦截
- 9个 OpenClaw 生命周期 Hook 集成
- 3个验证场景 System Prompts
- 单元测试：command-obfuscation、encoding-guard、intent-alignment
- 集成测试：间接提示词注入场景、数据外泄场景
- 架构设计文档
