// ============================================================
// ClawArmor 专属配置文件加载器
// 从 claw-armor.config.json 中读取插件独立配置
// 优先级：用户配置目录 > 插件安装目录 > 默认空配置
// ============================================================

import fs from "node:fs";
import path from "node:path";
import os from "node:os";

// ---- 配置文件查找路径（按优先级排列）----

function resolveSearchPaths(resolvePath?: (p: string) => string): string[] {
  const paths: string[] = [];

  // 1. 优先从 OpenClaw 解析的路径查找（如 resolvePath 指向 ~/.openclaw）
  if (resolvePath) {
    try {
      paths.push(resolvePath("plugins/claw-armor/claw-armor.config.json"));
    } catch { /* 忽略解析失败 */ }
  }

  // 2. ~/.openclaw/plugins/claw-armor/claw-armor.config.json（用户可编辑的标准位置）
  paths.push(
    path.join(os.homedir(), ".openclaw", "plugins", "claw-armor", "claw-armor.config.json"),
  );

  // 3. ~/.openclaw/extensions/claw-armor/claw-armor.config.json（插件安装目录）
  paths.push(
    path.join(os.homedir(), ".openclaw", "extensions", "claw-armor", "claw-armor.config.json"),
  );

  // 4. 当前工作目录（开发/调试用）
  paths.push(path.join(process.cwd(), "claw-armor.config.json"));

  return [...new Set(paths)];
}

// ---- 加载配置文件 ----

export function loadArmorConfigFile(
  resolvePath?: (p: string) => string,
): { raw: Record<string, unknown>; loadedFrom: string | null } {
  const searchPaths = resolveSearchPaths(resolvePath);

  for (const configPath of searchPaths) {
    try {
      if (!fs.existsSync(configPath)) continue;
      const content = fs.readFileSync(configPath, "utf-8");
      const raw = JSON.parse(content) as Record<string, unknown>;
      return { raw, loadedFrom: configPath };
    } catch {
      // 文件存在但解析失败，继续尝试下一个路径
    }
  }

  return { raw: {}, loadedFrom: null };
}

// ---- 将新格式 JSON 翻译为配置键空间（供 resolveClawArmorPluginConfig 使用）----

export function translateArmorConfigFile(raw: Record<string, unknown>): Record<string, unknown> {
  if (!raw || typeof raw !== "object") return {};
  const result: Record<string, unknown> = {};

  // 顶级字段直接透传
  if ("allDefensesEnabled" in raw) result.allDefensesEnabled = raw.allDefensesEnabled;
  if ("defaultBlockingMode" in raw) result.defaultBlockingMode = raw.defaultBlockingMode;

  // fastPath 段 → 展开为扁平字段
  const fp = (raw.fastPath ?? {}) as Record<string, unknown>;

  const mapSection = (
    section: unknown,
    enabledKey: string,
    modeKey: string,
  ) => {
    const s = (section ?? {}) as Record<string, unknown>;
    if ("enabled" in s) result[enabledKey] = s.enabled;
    if ("mode" in s) result[modeKey] = s.mode;
  };

  mapSection(fp.selfProtection,       "selfProtectionEnabled",       "selfProtectionMode");
  mapSection(fp.commandBlock,         "commandBlockEnabled",         "commandBlockMode");
  mapSection(fp.encodingGuard,        "encodingGuardEnabled",        "encodingGuardMode");
  mapSection(fp.scriptProvenanceGuard,"scriptProvenanceGuardEnabled","scriptProvenanceGuardMode");
  mapSection(fp.memoryGuard,          "memoryGuardEnabled",          "memoryGuardMode");
  mapSection(fp.loopGuard,            "loopGuardEnabled",            "loopGuardMode");
  mapSection(fp.exfiltrationGuard,    "exfiltrationGuardEnabled",    "exfiltrationGuardMode");

  // 单开关 sections
  const boolSection = (section: unknown, key: string) => {
    const s = (section ?? {}) as Record<string, unknown>;
    if ("enabled" in s) result[key] = s.enabled;
  };
  boolSection(fp.userRiskScan,   "userRiskScanEnabled");
  boolSection(fp.toolResultScan, "toolResultScanEnabled");
  boolSection(fp.outputRedaction,"outputRedactionEnabled");
  boolSection(fp.promptGuard,    "promptGuardEnabled");
  boolSection(fp.taintTracking,  "taintTrackingEnabled");

  // skillScan
  const ss = (fp.skillScan ?? {}) as Record<string, unknown>;
  if ("enabled" in ss) result.skillScanEnabled = ss.enabled;
  if ("startupScan" in ss) result.startupSkillScan = ss.startupScan;
  if (Array.isArray(ss.roots)) result.skillRoots = ss.roots;

  // selfProtection 资产配置
  const sp = (fp.selfProtection ?? {}) as Record<string, unknown>;
  if (Array.isArray(sp.protectedPaths))    result.protectedPaths    = sp.protectedPaths;
  if (Array.isArray(sp.protectedSkillIds)) result.protectedSkills   = sp.protectedSkillIds;
  if (Array.isArray(sp.protectedPluginIds))result.protectedPlugins  = sp.protectedPluginIds;

  // loopGuard.maxCallsPerRun
  const lg = (fp.loopGuard ?? {}) as Record<string, unknown>;
  if (typeof lg.maxCallsPerRun === "number") result.loopGuardMaxCalls = lg.maxCallsPerRun;

  // slowEngine 段 → 展开为 slowEngine 字段
  const se = (raw.slowEngine ?? {}) as Record<string, unknown>;
  if (Object.keys(se).length > 0) {
    const model = (se.model ?? {}) as Record<string, unknown>;
    const provider = typeof model.provider === "string" ? model.provider : "disabled";
    const ollama = (model.ollama ?? {}) as Record<string, unknown>;
    const oac   = (model.openaiCompat ?? {}) as Record<string, unknown>;

    const ia = (se.intentAlignment ?? {}) as Record<string, unknown>;
    const cf = (se.controlFlowCheck ?? {}) as Record<string, unknown>;
    const df = (se.dataFlowCheck ?? {}) as Record<string, unknown>;

    result.slowEngine = {
      enabled: se.enabled !== false && provider !== "disabled",
      mode: provider,
      ollamaBaseUrl:        typeof ollama.baseUrl === "string"  ? ollama.baseUrl  : "http://localhost:11434",
      ollamaModel:          typeof ollama.model === "string"    ? ollama.model    : "llama3",
      openaiCompatBaseUrl:  typeof oac.baseUrl === "string"     ? oac.baseUrl     : "https://api.deepseek.com/v1",
      openaiCompatModel:    typeof oac.model === "string"       ? oac.model       : "deepseek-chat",
      openaiCompatApiKey:   typeof oac.apiKey === "string"      ? oac.apiKey      : "",
      openaiCompatApiKeyEnv:typeof oac.apiKeyEnvVar === "string"? oac.apiKeyEnvVar: "",
      intentAlignmentEnabled:   ia.enabled !== false,
      controlFlowCheckEnabled:  cf.enabled !== false,
      dataFlowCheckEnabled:     df.enabled !== false,
      timeoutMs: typeof ollama.timeoutMs === "number" ? ollama.timeoutMs
               : typeof oac.timeoutMs   === "number" ? oac.timeoutMs
               : 10_000,
    };
  }

  // customThreatPatterns 段 → 直接透传（在 resolveClawArmorPluginConfig 中处理）
  if (raw.customThreatPatterns && typeof raw.customThreatPatterns === "object") {
    result.customThreatPatterns = raw.customThreatPatterns;
  }

  return result;
}
