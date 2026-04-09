// ============================================================
// ClawArmor 核心生命周期 Hook 集成层
// 串联 Fast Path（规则引擎 + 防御链）与 Slow Path（旁路验证）
// ============================================================

import type { ClawArmorPluginConfig, DefenseMode } from "../config/index.js";
import {
  BLOCK_REASON_INTENT_HIJACK,
  BLOCK_REASON_TAINT_VIOLATION,
  BLOCK_REASON_DATA_EXFIL,
  BLOCK_REASON_HIGH_RISK_OPERATION,
  BLOCK_REASON_MEMORY_WRITE,
  BLOCK_REASON_PROTECTED_PATH,
  BLOCK_REASON_LOOP,
  BLOCK_REASON_EXFILTRATION_CHAIN,
} from "../config/index.js";
import type { BaselineIntent } from "../types/index.js";
import type { ArmorLogger } from "../logger/index.js";
import { TaintTracker } from "../taint-tracker/index.js";
import { ModelGateway } from "../engine-slow/gateway/index.js";
import { captureBaselineIntent, checkIntentAlignment } from "../engine-slow/checkers/intent-alignment.js";
import { checkDataFlowConfidentiality } from "../engine-slow/checkers/data-flow.js";
import { SessionStateManager } from "../session-state.js";
import { SkillWatcher } from "../engine-fast/skill-watcher.js";
import {
  scanUserInput,
  scanToolCallParams,
  scanToolResult,
  scanMemoryWrite,
  analyzeToolCallForExfil,
  redactOutput,
  detectPiiTypes,
} from "../engine-fast/rule-engine.js";
import { redactSecretVariants } from "../engine-fast/payload-scanner.js";
import {
  runDefenseChain,
  PROMPT_GUARD_STATIC,
  PROMPT_GUARD_DYNAMIC,
  type DefenseModeConfig,
  type ToolCallContext,
} from "../engine-fast/defense-chain.js";
import type { ExfilChainState } from "../engine-fast/rule-engine.js";

// ============================================================
// Hook 结果类型
// ============================================================

export type HookVerdict =
  | { action: "allow"; sanitizedResult?: string }
  | { action: "block"; reason: string }
  | { action: "observe"; reason: string; flags: string[] };

// ============================================================
// ClawArmor Runtime
// ============================================================

export type ClawArmorRuntime = {
  state: SessionStateManager;
  taintTracker: TaintTracker;
  gateway: ModelGateway;
  skillWatcher: SkillWatcher;
  baselineIntents: Map<string, BaselineIntent>;
  /** runId → 外泄链状态 */
  exfilStates: Map<string, ExfilChainState>;
  /** runId → 本次 run 内写入的高风险脚本路径 */
  riskyScriptPaths: Map<string, Set<string>>;
  /** runId → loop 计数器 */
  loopCallCounts: Map<string, Map<string, number>>;
  hooks: ClawArmorHooks;
};

export type ClawArmorHooks = {
  onAgentStart(e: { sessionKey: string; runId: string; userInput: string }): Promise<HookVerdict>;
  beforeToolCall(e: { sessionKey: string; runId: string; toolName: string; params: Record<string, unknown> }): Promise<HookVerdict>;
  afterToolCall(e: { sessionKey: string; runId: string; toolName: string; result: string; isExternal: boolean }): Promise<HookVerdict>;
  onPlanGenerated(e: { sessionKey: string; runId: string; plan: string }): Promise<HookVerdict>;
  onMemoryWrite(e: { sessionKey: string; key: string; content: string }): Promise<HookVerdict>;
  beforeAgentReply(e: { sessionKey: string; content: string }): { content: string; redactedCount: number };
  buildPromptContext(sessionKey: string): string;
  onSessionEnd(sessionKey: string): Promise<void>;
  onRunEnd(runId: string): Promise<void>;
};

// ============================================================
// 外部工具判断
// ============================================================

const EXTERNAL_TOOL_RE = /^(?:web_fetch|web_search|browser|firecrawl_\w+|tavily_\w+|http_request|api|url_fetch)$/i;
function isExternalTool(toolName: string): boolean { return EXTERNAL_TOOL_RE.test(toolName); }

const OUTBOUND_TOOL_RE = /^(?:curl|wget|http_request|web_fetch|fetch|url_fetch)$/i;
function isOutboundTool(toolName: string): boolean { return OUTBOUND_TOOL_RE.test(toolName); }

// ============================================================
// 防御模式配置提取
// ============================================================

function buildDefenseModes(config: ClawArmorPluginConfig): DefenseModeConfig {
  return {
    selfProtection: config.selfProtectionMode,
    commandBlock: config.commandBlockMode,
    encodingGuard: config.encodingGuardMode,
    memoryGuard: config.memoryGuardMode,
    scriptProvenance: config.scriptProvenanceGuardMode,
    loopGuard: config.loopGuardMode,
    exfiltrationGuard: config.exfiltrationGuardMode,
  };
}

// ============================================================
// 工厂函数
// ============================================================

export function createClawArmorRuntime(
  config: ClawArmorPluginConfig,
  logger: ArmorLogger,
  stateDir: string,
): ClawArmorRuntime {
  const log = logger.child({ module: "hooks" });
  const state = new SessionStateManager(stateDir, logger);
  const taintTracker = new TaintTracker();
  const gateway = new ModelGateway(config.slowEngine);
  const skillWatcher = new SkillWatcher(logger);
  const baselineIntents = new Map<string, BaselineIntent>();
  const exfilStates = new Map<string, ExfilChainState>();
  const riskyScriptPaths = new Map<string, Set<string>>();
  const loopCallCounts = new Map<string, Map<string, number>>();

  const defenseModes = buildDefenseModes(config);

  function getOrCreateExfilState(runId: string): ExfilChainState {
    if (!exfilStates.has(runId)) {
      exfilStates.set(runId, { sourceSignals: [], transformSignals: [], sinkSignals: [] });
    }
    return exfilStates.get(runId)!;
  }

  function getOrCreateLoopCounts(runId: string): Map<string, number> {
    if (!loopCallCounts.has(runId)) loopCallCounts.set(runId, new Map());
    return loopCallCounts.get(runId)!;
  }

  function getOrCreateRiskyPaths(runId: string): Set<string> {
    if (!riskyScriptPaths.has(runId)) riskyScriptPaths.set(runId, new Set());
    return riskyScriptPaths.get(runId)!;
  }

  const hooks: ClawArmorHooks = {

    // ----------------------------------------------------------
    // Hook 1: Agent 启动
    // ----------------------------------------------------------
    async onAgentStart({ sessionKey, runId, userInput }) {
      // 捕获基准意图（供 Slow Path 意图对齐使用）
      baselineIntents.set(sessionKey, captureBaselineIntent(sessionKey, userInput));

      // 用户输入威胁扫描（Fast Path）
      if (config.userRiskScanEnabled && userInput) {
        const report = scanUserInput(userInput);
        if (report.isSuspicious) {
          state.appendTurnFlags(sessionKey, { injectionFlags: report.flags });
          log.warn("[ClawArmor] 用户输入检测到风险模式", { flags: report.flags });
        }
      }

      // 用户输入 PII 检测：检测到个人敏感数据后注入脱敏指令到下一轮系统提示词
      if (config.outputRedactionEnabled && userInput) {
        const piiTypes = detectPiiTypes(userInput);
        if (piiTypes.length > 0) {
          state.appendTurnFlags(sessionKey, { runtimeFlags: [`pii-in-input:${piiTypes.join(",")}`] });
          log.warn("[ClawArmor] 用户输入含个人敏感数据，将注入脱敏指令", { types: piiTypes });
        }
      }

      // 启动时 Skill 扫描
      if (config.skillScanEnabled && config.startupSkillScan) {
        const skillRoots = config.skillRoots.length > 0 ? config.skillRoots : [];
        skillWatcher.scanRoots(skillRoots, 200).then((records) => {
          const risky = records.filter((r) => !r.isTrusted);
          if (risky.length > 0) {
            state.appendTurnFlags(sessionKey, {
              skillRiskFlags: risky.flatMap((r) => r.findings),
            });
            log.warn("[ClawArmor] 启动扫描发现高风险 Skill", { count: risky.length });
          }
        }).catch(() => undefined);
      }

      return { action: "allow" };
    },

    // ----------------------------------------------------------
    // Hook 2: 工具调用前（最核心的防御节点）
    // ----------------------------------------------------------
    async beforeToolCall({ sessionKey, runId, toolName, params }) {
      log.debug("[ClawArmor] 拦截工具调用", { toolName, paramKeys: Object.keys(params) });
      const loopCounts = getOrCreateLoopCounts(runId);
      const riskyPaths = getOrCreateRiskyPaths(runId);

      const ctx: ToolCallContext = {
        toolName,
        params,
        runId,
        sessionKey,
        workspaceRoot: process.cwd(),
        priorSourceSignals: getOrCreateExfilState(runId).sourceSignals,
        priorSinkSignals: getOrCreateExfilState(runId).sinkSignals,
        priorTransformSignals: getOrCreateExfilState(runId).transformSignals,
      };

      // 防御链（Fast Path）
      const verdict = runDefenseChain({
        ctx,
        modes: defenseModes,
        protectedPaths: config.protectedPaths,
        protectedSkillIds: config.protectedSkills,
        protectedPluginIds: config.protectedPlugins,
        riskyScriptPaths: riskyPaths,
        loopCallCounts: loopCounts,
        customPatterns: config.customPatterns,
      });

      if (verdict.action === "block") {
        return { action: "block", reason: verdict.reason ?? BLOCK_REASON_HIGH_RISK_OPERATION };
      }
      if (verdict.action === "observe") {
        state.appendTurnFlags(sessionKey, { runtimeFlags: verdict.matchedFlags });
        log.warn("[ClawArmor] 工具调用观察告警", { layer: verdict.layer, flags: verdict.matchedFlags });
        return { action: "observe", reason: verdict.reason ?? "", flags: verdict.matchedFlags };
      }

      // 污点追踪：低完整性数据 → 高权限工具（Fast Path）
      if (config.taintTrackingEnabled) {
        const taintCheck = taintTracker.checkControlFlowViolation(toolName, params);
        if (taintCheck.violated && taintCheck.reason) {
          log.warn("[ClawArmor] 污点控制流违规", { toolName });
          if (config.commandBlockMode === "enforce") {
            return { action: "block", reason: BLOCK_REASON_TAINT_VIOLATION };
          }
          return { action: "observe", reason: BLOCK_REASON_TAINT_VIOLATION, flags: ["taint-control-flow"] };
        }
      }

      // 数据流熔断：出站工具的 PII/凭证检测（Fast + Slow Path）
      if (config.exfiltrationGuardEnabled && isOutboundTool(toolName)) {
        const contextText = JSON.stringify(params);
        const dfResult = await checkDataFlowConfidentiality(gateway, toolName, params, contextText);
        if (!dfResult.safe) {
          log.warn("[ClawArmor] 数据流熔断触发", { toolName, pii: dfResult.piiDetected });
          if (config.exfiltrationGuardMode === "enforce") {
            return { action: "block", reason: BLOCK_REASON_DATA_EXFIL };
          }
          return { action: "observe", reason: BLOCK_REASON_DATA_EXFIL, flags: ["data-exfil"] };
        }
      }

      // 更新外泄链状态
      const priorExfil = getOrCreateExfilState(runId);
      const { updatedState } = analyzeToolCallForExfil(toolName, params, priorExfil);
      exfilStates.set(runId, updatedState);

      return { action: "allow" };
    },

    // ----------------------------------------------------------
    // Hook 3: 工具调用后
    // ----------------------------------------------------------
    async afterToolCall({ sessionKey, runId, toolName, result, isExternal }) {
      // 工具结果扫描（Fast Path）
      if (config.toolResultScanEnabled) {
        const report = scanToolResult(toolName, result, isExternal);
        state.appendTurnFlags(sessionKey, {
          toolResultFlags: report.flags,
          hasExternalToolResult: isExternal,
          isToolResultSuspicious: report.isSuspicious,
          isToolResultOversize: report.isOversize,
        });
        if (report.isSuspicious) {
          log.warn("[ClawArmor] 工具返回结果存在可疑内容", { toolName, flags: report.flags });
        }
      }

      // 污点标记（外部来源 → 低完整性）
      if (config.taintTrackingEnabled && (isExternal || isExternalTool(toolName))) {
        taintTracker.taintToolResult(toolName, result);
      }

      // 工具结果 PII 检测：检测到敏感数据后向下一轮系统提示词注入脱敏指令
      // （这是主防御层，因为 after_tool_call 返回值在当前 OpenClaw 版本中不被用于修改内容）
      if (config.outputRedactionEnabled && result.length > 0) {
        const piiTypes = detectPiiTypes(result);
        if (piiTypes.length > 0) {
          state.appendTurnFlags(sessionKey, { runtimeFlags: [`pii-in-tool:${piiTypes.join(",")}`] });
          log.warn("[ClawArmor] 工具返回含个人敏感数据，将注入脱敏指令", { toolName, types: piiTypes });
        }

        // 尝试通过返回值修改工具结果（若当前 OpenClaw 版本支持则生效，否则由 prompt 指令兜底）
        const { result: redacted, redactedCount } = redactOutput(result, config.customPatterns.sensitiveDataRedaction);
        if (redactedCount > 0) {
          log.info("[ClawArmor] 工具返回结果敏感数据脱敏（返回值方式）", { toolName, redactedCount });
          return { action: "allow" as const, sanitizedResult: redacted };
        }
      }

      return { action: "allow" as const };
    },

    // ----------------------------------------------------------
    // Hook 4: 规划生成后（Slow Path 意图对齐核心）
    // ----------------------------------------------------------
    async onPlanGenerated({ sessionKey, runId, plan }) {
      if (!config.slowEngine.enabled || !config.slowEngine.intentAlignmentEnabled) {
        return { action: "allow" };
      }
      const baseline = baselineIntents.get(sessionKey);
      if (!baseline) return { action: "allow" };

      const alignResult = await checkIntentAlignment(gateway, baseline, plan);

      if (alignResult.verdict === "hijacked") {
        log.warn("[ClawArmor] 意图对齐：检测到意图劫持", { deviation: alignResult.deviation });
        return { action: "block", reason: BLOCK_REASON_INTENT_HIJACK };
      }

      if (alignResult.verdict === "suspect") {
        state.appendTurnFlags(sessionKey, { runtimeFlags: ["intent-suspect"] });
        log.warn("[ClawArmor] 意图对齐：计划存在可疑偏离", { confidence: alignResult.confidence });
        return { action: "observe", reason: "计划偏离用户意图", flags: ["intent-suspect"] };
      }

      return { action: "allow" };
    },

    // ----------------------------------------------------------
    // Hook 5: 记忆写入审计
    // ----------------------------------------------------------
    async onMemoryWrite({ sessionKey, key, content }) {
      if (!config.memoryGuardEnabled) return { action: "allow" };

      const report = scanMemoryWrite(key, content);
      if (!report.isAllowed) {
        log.warn("[ClawArmor] 记忆写入审计阻断", { key, flags: report.flags });
        if (config.memoryGuardMode === "enforce") {
          return { action: "block", reason: BLOCK_REASON_MEMORY_WRITE };
        }
        return { action: "observe", reason: report.blockReason ?? "", flags: report.flags };
      }
      return { action: "allow" };
    },

    // ----------------------------------------------------------
    // Hook 6: 输出脱敏（同步，因为 before_message_write 是同步钩子）
    // ----------------------------------------------------------
    beforeAgentReply({ sessionKey, content }) {
      if (!config.outputRedactionEnabled) return { content, redactedCount: 0 };

      let processed = content;

      // 已观测密钥变体脱敏
      let variantRedactedCount = 0;
      const observedSecrets = state.getObservedSecrets(sessionKey);
      if (observedSecrets.length > 0) {
        const { text, count } = redactSecretVariants(processed, observedSecrets, "[已脱敏]");
        processed = text;
        variantRedactedCount = count ?? 0;
      }

      // 固定格式脱敏（含用户自定义脱敏规则）
      const { result, redactedCount } = redactOutput(processed, config.customPatterns.sensitiveDataRedaction);
      if (result !== processed) {
        log.info("[ClawArmor] 输出脱敏完成", { sessionKey, redactedCount });
      }

      return { content: result, redactedCount: redactedCount + variantRedactedCount };
    },

    // ----------------------------------------------------------
    // Prompt 上下文构建（注入安全提示词）
    // ----------------------------------------------------------
    buildPromptContext(sessionKey: string): string {
      if (!config.promptGuardEnabled) return "";

      const parts: string[] = [
        PROMPT_GUARD_STATIC.selfProtection,
        PROMPT_GUARD_STATIC.externalData,
        PROMPT_GUARD_STATIC.disablePlugin,
        PROMPT_GUARD_STATIC.outputRedaction,
      ];

      const turn = state.peekTurnSignals(sessionKey);
      if (turn) {
        // PII 检测：注入强制脱敏指令（优先注入，排在其他告警之前）
        const piiFlags = turn.runtimeFlags.filter((f) => f.startsWith("pii-in-"));
        if (piiFlags.length > 0) {
          const piiTypes = new Set<string>();
          for (const f of piiFlags) {
            const typeStr = f.split(":")[1] ?? "";
            for (const t of typeStr.split(",")) { if (t) piiTypes.add(t); }
          }
          parts.push(PROMPT_GUARD_DYNAMIC.piiDetected([...piiTypes]));
        }

        if (turn.isToolResultSuspicious && turn.toolResultFlags.length > 0) {
          parts.push(PROMPT_GUARD_DYNAMIC.toolResultRisk(turn.toolResultFlags));
        }
        if (turn.skillRiskFlags.length > 0) {
          parts.push(PROMPT_GUARD_DYNAMIC.skillRisk(turn.skillRiskFlags));
        }
        if (turn.injectionFlags.length > 0) {
          parts.push(PROMPT_GUARD_DYNAMIC.userRisk(turn.injectionFlags));
        }
      }

      return parts.join("\n");
    },

    // ----------------------------------------------------------
    // Hook 7: 会话结束清理
    // ----------------------------------------------------------
    async onSessionEnd(sessionKey: string) {
      state.clearSession(sessionKey);
      baselineIntents.delete(sessionKey);
      taintTracker.clear();
      log.debug("[ClawArmor] 会话已清理", { sessionKey });
    },

    // ----------------------------------------------------------
    // Hook 8: Run 结束清理
    // ----------------------------------------------------------
    async onRunEnd(runId: string) {
      state.clearRun(runId);
      exfilStates.delete(runId);
      riskyScriptPaths.delete(runId);
      loopCallCounts.delete(runId);
    },
  };

  return { state, taintTracker, gateway, skillWatcher, baselineIntents, exfilStates, riskyScriptPaths, loopCallCounts, hooks };
}
