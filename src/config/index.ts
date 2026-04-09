import path from "node:path";
import type { ClawArmorSlowEngineConfig } from "../types/index.js";
import { loadArmorConfigFile, translateArmorConfigFile } from "./file-loader.js";

// ============================================================
// 插件 ID
// ============================================================

export const CLAW_ARMOR_PLUGIN_ID = "claw-armor";

// ============================================================
// 防御模式
// ============================================================

export const DEFENSE_MODES = ["off", "observe", "enforce"] as const;
export type DefenseMode = (typeof DEFENSE_MODES)[number];

// ============================================================
// 时间与容量常量（继承自 ClawAegis）
// ============================================================

export const TURN_STATE_TTL_MS = 5 * 60_000;
export const LOOP_GUARD_TTL_MS = 5 * 60_000;
export const LOOP_GUARD_ALLOW_COUNT = 3;

export const STARTUP_SCAN_BUDGET_MS = 200;
export const INLINE_EXEC_TEXT_MAX_CHARS = 8 * 1024;
export const MEMORY_WRITE_MAX_CHARS = 8 * 1024;
export const MEMORY_WRITE_MAX_LINES = 200;
export const TOOL_RESULT_CHAR_BUDGET = 64 * 1024;
export const TOOL_RESULT_MAX_DEPTH = 4;
export const TOOL_RESULT_MAX_ARRAY_ITEMS = 200;

export const SKILL_SCAN_QUEUE_MAX = 16;
export const SKILL_SCAN_TIMEOUT_MS = 3000;
export const SKILL_SCAN_COOLDOWN_MS = 5 * 60_000;
export const SKILL_SCAN_FAILURE_WINDOW_MS = 60_000;
export const SKILL_SCAN_FAILURE_THRESHOLD = 3;
export const SKILL_SCAN_FILE_MAX_BYTES = 100 * 1024;
export const SKILL_SCAN_TARGET_FILENAME = "SKILL.md";

export const TRUSTED_SKILLS_FILENAME = "trusted-skills.json";
export const SELF_INTEGRITY_FILENAME = "self-integrity.json";

// ============================================================
// 阻断原因消息（中文，继承自 ClawAegis）
// ============================================================

export const BLOCK_REASON_PROTECTED_PATH =
  "安全限制：禁止访问、查询、修改、删除、关闭或绕过受保护的敏感路径、配置、重要 skill 或 claw-armor 插件目录。";
export const BLOCK_REASON_WORKSPACE_DELETE =
  "安全限制：禁止删除 workspace 之外的路径。";
export const BLOCK_REASON_OPENCLAW_COMMAND =
  "安全限制：禁止执行 openclaw CLI 或控制命令。";
export const BLOCK_REASON_HIGH_RISK_OPERATION = "安全限制：已阻止本次高风险操作请求。";
export const BLOCK_REASON_MEMORY_WRITE = "安全限制：已拒绝本次高风险记忆写入。";
export const BLOCK_REASON_LOOP = "安全限制：检测到重复高风险工具调用，已停止本次操作。";
export const BLOCK_REASON_EXFILTRATION_CHAIN =
  "安全限制：检测到疑似 SSRF 或数据外泄工具调用链，已阻止本次出站请求。";

// ============================================================
// ClawArmor 新增阻断原因
// ============================================================

export const BLOCK_REASON_INTENT_HIJACK =
  "安全限制：ClawArmor 语义对齐引擎检测到 Agent 决策路径与用户原始意图严重偏离，疑似间接提示词注入攻击，已终止执行。";
export const BLOCK_REASON_TAINT_VIOLATION =
  "安全限制：ClawArmor 污点追踪引擎检测到低完整性外部数据试图驱动高权限工具调用，已阻断。";
export const BLOCK_REASON_DATA_EXFIL =
  "安全限制：ClawArmor 数据流熔断引擎检测到高敏感数据（PII/凭证）试图外发至非受信地址，已物理熔断。";

// ============================================================
// 自定义威胁模式类型
// ============================================================

/** claw-armor.config.json 中 customThreatPatterns 各项的原始结构 */
export type CustomThreatPatternDef = {
  id: string;
  /** 正则字符串，加载时编译为 RegExp */
  regex: string;
  description?: string;
};

/** 已编译为 RegExp 的自定义模式（供防御链直接使用） */
export type CompiledCustomPattern = {
  id: string;
  regex: RegExp;
};

/** 四类自定义威胁模式（编译后） */
export type CompiledCustomPatterns = {
  /** 受保护路径模式（扩展内置路径防护） */
  protectedPaths: CompiledCustomPattern[];
  /** 危险命令模式（扩展内置命令拦截） */
  dangerousCommands: CompiledCustomPattern[];
  /** 输出脱敏模式（扩展内置凭证脱敏） */
  sensitiveDataRedaction: CompiledCustomPattern[];
  /** 注入检测模式（扩展内置注入扫描） */
  injectionDetection: CompiledCustomPattern[];
};

const EMPTY_CUSTOM_PATTERNS: CompiledCustomPatterns = {
  protectedPaths: [],
  dangerousCommands: [],
  sensitiveDataRedaction: [],
  injectionDetection: [],
};

// ============================================================
// ClawArmor 完整配置类型
// ============================================================

export type ClawArmorPluginConfig = {
  // ---- 全局开关 ----
  allDefensesEnabled: boolean;
  defaultBlockingMode: DefenseMode;

  // ---- Fast Path：静态规则引擎（继承自 ClawAegis）----
  selfProtectionEnabled: boolean;
  selfProtectionMode: DefenseMode;
  commandBlockEnabled: boolean;
  commandBlockMode: DefenseMode;
  encodingGuardEnabled: boolean;
  encodingGuardMode: DefenseMode;
  scriptProvenanceGuardEnabled: boolean;
  scriptProvenanceGuardMode: DefenseMode;
  memoryGuardEnabled: boolean;
  memoryGuardMode: DefenseMode;
  userRiskScanEnabled: boolean;
  skillScanEnabled: boolean;
  toolResultScanEnabled: boolean;
  outputRedactionEnabled: boolean;
  promptGuardEnabled: boolean;
  loopGuardEnabled: boolean;
  loopGuardMode: DefenseMode;
  exfiltrationGuardEnabled: boolean;
  exfiltrationGuardMode: DefenseMode;

  // ---- 资产保护 ----
  protectedPaths: string[];
  protectedSkills: string[];
  protectedPlugins: string[];
  skillRoots: string[];
  extraProtectedRoots: string[];
  startupSkillScan: boolean;

  // ---- Slow Path：动态旁路验证引擎（ClawArmor 新增）----
  slowEngine: ClawArmorSlowEngineConfig;

  // ---- 污点追踪（ClawArmor 新增）----
  taintTrackingEnabled: boolean;

  // ---- 自定义威胁模式（来自 claw-armor.config.json）----
  customPatterns: CompiledCustomPatterns;

  /** 配置文件实际加载路径，null 表示使用默认值 */
  configFilePath: string | null;
};

// ============================================================
// 默认配置
// ============================================================

export const DEFAULT_SLOW_ENGINE_CONFIG: ClawArmorSlowEngineConfig = {
  enabled: false,
  mode: "disabled",
  ollamaBaseUrl: "http://localhost:11434",
  ollamaModel: "llama3",
  openaiCompatBaseUrl: "https://api.deepseek.com/v1",
  openaiCompatModel: "deepseek-chat",
  openaiCompatApiKey: "",
  intentAlignmentEnabled: true,
  controlFlowCheckEnabled: true,
  dataFlowCheckEnabled: true,
  timeoutMs: 10_000,
};

// ============================================================
// 配置解析工具函数
// ============================================================

function isDefenseMode(value: unknown): value is DefenseMode {
  return typeof value === "string" && (DEFENSE_MODES as readonly string[]).includes(value);
}

function normalizeStringList(value: unknown, resolvePath: (input: string) => string): string[] {
  if (!Array.isArray(value)) return [];
  const seen = new Set<string>();
  const results: string[] = [];
  for (const entry of value) {
    if (typeof entry !== "string") continue;
    const trimmed = entry.trim();
    if (!trimmed) continue;
    const resolved = path.resolve(resolvePath(trimmed));
    if (seen.has(resolved)) continue;
    seen.add(resolved);
    results.push(resolved);
  }
  return results;
}

function normalizeIdentifierList(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const seen = new Set<string>();
  const results: string[] = [];
  for (const entry of value) {
    if (typeof entry !== "string") continue;
    const normalized = entry.trim().normalize("NFKC").toLowerCase();
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    results.push(normalized);
  }
  return results;
}

function readEnabledFlag(raw: Record<string, unknown>, key: string, allEnabled: boolean): boolean {
  return allEnabled && raw[key] !== false;
}

function readDefenseMode(
  raw: Record<string, unknown>,
  enabledKey: string,
  modeKey: string,
  defaultMode: DefenseMode,
  allEnabled: boolean,
): DefenseMode {
  if (!allEnabled || raw[enabledKey] === false) return "off";
  const explicit = raw[modeKey];
  return isDefenseMode(explicit) ? explicit : defaultMode;
}

function resolveSlowEngineConfig(raw: Record<string, unknown>): ClawArmorSlowEngineConfig {
  const slow = (raw.slowEngine ?? {}) as Record<string, unknown>;
  const mode = (["ollama", "openai-compat", "disabled"] as const).includes(slow.mode as never)
    ? (slow.mode as ClawArmorSlowEngineConfig["mode"])
    : "disabled";

  // 支持 openaiCompatApiKeyEnv —— 从环境变量读取 API Key
  let apiKey = typeof slow.openaiCompatApiKey === "string" ? slow.openaiCompatApiKey : "";
  if (!apiKey) {
    const envVar = typeof slow.openaiCompatApiKeyEnv === "string" ? slow.openaiCompatApiKeyEnv : "";
    if (envVar) apiKey = process.env[envVar] ?? "";
  }

  return {
    enabled: slow.enabled !== false && mode !== "disabled",
    mode,
    ollamaBaseUrl:       typeof slow.ollamaBaseUrl       === "string" ? slow.ollamaBaseUrl       : DEFAULT_SLOW_ENGINE_CONFIG.ollamaBaseUrl,
    ollamaModel:         typeof slow.ollamaModel         === "string" ? slow.ollamaModel         : DEFAULT_SLOW_ENGINE_CONFIG.ollamaModel,
    openaiCompatBaseUrl: typeof slow.openaiCompatBaseUrl === "string" ? slow.openaiCompatBaseUrl : DEFAULT_SLOW_ENGINE_CONFIG.openaiCompatBaseUrl,
    openaiCompatModel:   typeof slow.openaiCompatModel   === "string" ? slow.openaiCompatModel   : DEFAULT_SLOW_ENGINE_CONFIG.openaiCompatModel,
    openaiCompatApiKey:  apiKey,
    intentAlignmentEnabled:  slow.intentAlignmentEnabled  !== false,
    controlFlowCheckEnabled: slow.controlFlowCheckEnabled !== false,
    dataFlowCheckEnabled:    slow.dataFlowCheckEnabled    !== false,
    timeoutMs: typeof slow.timeoutMs === "number" ? slow.timeoutMs : DEFAULT_SLOW_ENGINE_CONFIG.timeoutMs,
  };
}

/**
 * 解析 claw-armor.config.json 中的自定义威胁模式
 * 无效的正则表达式会被跳过（fail-open）
 */
function resolveCustomPatterns(raw: Record<string, unknown>): CompiledCustomPatterns {
  const src = (raw.customThreatPatterns ?? {}) as Record<string, unknown>;
  if (!src || typeof src !== "object") return EMPTY_CUSTOM_PATTERNS;

  const compileList = (list: unknown): CompiledCustomPattern[] => {
    if (!Array.isArray(list)) return [];
    const result: CompiledCustomPattern[] = [];
    for (const item of list) {
      if (!item || typeof item !== "object") continue;
      const def = item as CustomThreatPatternDef;
      if (!def.id || typeof def.id !== "string") continue;
      if (!def.regex || typeof def.regex !== "string") continue;
      try {
        result.push({ id: def.id.trim(), regex: new RegExp(def.regex, "i") });
      } catch {
        // 无效正则跳过，不影响主流程
      }
    }
    return result;
  };

  return {
    protectedPaths:       compileList(src.protectedPaths),
    dangerousCommands:    compileList(src.dangerousCommands),
    sensitiveDataRedaction: compileList(src.sensitiveDataRedaction),
    injectionDetection:   compileList(src.injectionDetection),
  };
}

/**
 * 合并两个原始配置对象，fileConfig 为基础，pluginConfig 中存在的非空值会覆盖
 * 注意：customThreatPatterns 数组采用合并（追加）而非覆盖
 */
function mergeRawConfigs(
  fileConfig: Record<string, unknown>,
  pluginConfig: Record<string, unknown>,
): Record<string, unknown> {
  const merged: Record<string, unknown> = { ...fileConfig };

  for (const [key, value] of Object.entries(pluginConfig)) {
    if (key === "customThreatPatterns") {
      // 自定义模式：合并追加
      const filePatterns = (fileConfig.customThreatPatterns ?? {}) as Record<string, unknown>;
      const pluginPatterns = (value ?? {}) as Record<string, unknown>;
      const mergedPatterns: Record<string, unknown> = {};
      const categories = ["protectedPaths", "dangerousCommands", "sensitiveDataRedaction", "injectionDetection"];
      for (const cat of categories) {
        const fp = Array.isArray(filePatterns[cat]) ? filePatterns[cat] as unknown[] : [];
        const pp = Array.isArray(pluginPatterns[cat]) ? pluginPatterns[cat] as unknown[] : [];
        mergedPatterns[cat] = [...fp, ...pp];
      }
      merged.customThreatPatterns = mergedPatterns;
    } else if (value !== undefined && value !== null) {
      merged[key] = value;
    }
  }

  return merged;
}

/**
 * 从专属配置文件 + 可选的 openclaw.json pluginConfig 解析 ClawArmor 完整配置。
 *
 * 加载优先级：
 *   claw-armor.config.json (文件) → openclaw.json pluginConfig（覆盖） → 内置默认值
 */
export function resolveClawArmorPluginConfig(
  pluginConfig: Record<string, unknown>,
  resolvePath: (input: string) => string,
): ClawArmorPluginConfig {
  // 1. 加载专属配置文件
  const { raw: fileRaw, loadedFrom } = loadArmorConfigFile(resolvePath);
  const translated = translateArmorConfigFile(fileRaw);

  // 2. 合并：文件配置为基础，openclaw.json pluginConfig 中的显式配置覆盖
  const raw = mergeRawConfigs(translated, pluginConfig);

  // 3. 解析配置
  const allDefensesEnabled = raw.allDefensesEnabled !== false;
  const defaultBlockingMode = isDefenseMode(raw.defaultBlockingMode) ? raw.defaultBlockingMode : "enforce";

  const selfProtectionMode        = readDefenseMode(raw, "selfProtectionEnabled",        "selfProtectionMode",        defaultBlockingMode, allDefensesEnabled);
  const commandBlockMode          = readDefenseMode(raw, "commandBlockEnabled",           "commandBlockMode",          defaultBlockingMode, allDefensesEnabled);
  const encodingGuardMode         = readDefenseMode(raw, "encodingGuardEnabled",          "encodingGuardMode",         defaultBlockingMode, allDefensesEnabled);
  const scriptProvenanceGuardMode = readDefenseMode(raw, "scriptProvenanceGuardEnabled",  "scriptProvenanceGuardMode", defaultBlockingMode, allDefensesEnabled);
  const memoryGuardMode           = readDefenseMode(raw, "memoryGuardEnabled",            "memoryGuardMode",           defaultBlockingMode, allDefensesEnabled);
  const loopGuardMode             = readDefenseMode(raw, "loopGuardEnabled",              "loopGuardMode",             defaultBlockingMode, allDefensesEnabled);
  const exfiltrationGuardMode     = readDefenseMode(raw, "exfiltrationGuardEnabled",      "exfiltrationGuardMode",     defaultBlockingMode, allDefensesEnabled);

  return {
    allDefensesEnabled,
    defaultBlockingMode,
    selfProtectionEnabled:        selfProtectionMode        !== "off",
    selfProtectionMode,
    commandBlockEnabled:          commandBlockMode          !== "off",
    commandBlockMode,
    encodingGuardEnabled:         encodingGuardMode         !== "off",
    encodingGuardMode,
    scriptProvenanceGuardEnabled: scriptProvenanceGuardMode !== "off",
    scriptProvenanceGuardMode,
    memoryGuardEnabled:           memoryGuardMode           !== "off",
    memoryGuardMode,
    userRiskScanEnabled:    readEnabledFlag(raw, "userRiskScanEnabled",    allDefensesEnabled),
    skillScanEnabled:       readEnabledFlag(raw, "skillScanEnabled",       allDefensesEnabled),
    toolResultScanEnabled:  readEnabledFlag(raw, "toolResultScanEnabled",  allDefensesEnabled),
    outputRedactionEnabled: readEnabledFlag(raw, "outputRedactionEnabled", allDefensesEnabled),
    promptGuardEnabled:     readEnabledFlag(raw, "promptGuardEnabled",     allDefensesEnabled),
    loopGuardEnabled:       loopGuardMode     !== "off",
    loopGuardMode,
    exfiltrationGuardEnabled: exfiltrationGuardMode !== "off",
    exfiltrationGuardMode,
    protectedPaths:       normalizeStringList(raw.protectedPaths,       resolvePath),
    protectedSkills:      normalizeIdentifierList(raw.protectedSkills),
    protectedPlugins:     normalizeIdentifierList(raw.protectedPlugins),
    skillRoots:           normalizeStringList(raw.skillRoots,           resolvePath),
    extraProtectedRoots:  normalizeStringList(raw.extraProtectedRoots,  resolvePath),
    startupSkillScan:     raw.startupSkillScan !== false,
    slowEngine:           resolveSlowEngineConfig(raw),
    taintTrackingEnabled: allDefensesEnabled && raw.taintTrackingEnabled !== false,
    customPatterns:       resolveCustomPatterns(raw),
    configFilePath:       loadedFrom,
  };
}
