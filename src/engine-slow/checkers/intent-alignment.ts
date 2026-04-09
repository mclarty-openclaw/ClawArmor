// ============================================================
// 意图一致性验证器（Slow Path）
// 核心防御：基准意图追踪 + 语义比对，对抗间接提示词注入
// ============================================================

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import type { IntentAlignmentResult, BaselineIntent } from "../../types/index.js";
import type { ModelGateway } from "../gateway/index.js";

// 从 prompts 目录加载 system prompt
function loadSystemPrompt(): string {
  try {
    const dir = path.dirname(fileURLToPath(import.meta.url));
    const promptPath = path.resolve(dir, "../../../prompts/intent-alignment.md");
    return readFileSync(promptPath, "utf8");
  } catch {
    return FALLBACK_SYSTEM_PROMPT;
  }
}

const FALLBACK_SYSTEM_PROMPT = `你是安全审计模块，判断 Agent 计划是否偏离用户意图。
输出 JSON: {"verdict":"safe|suspect|hijacked","confidence":0.0,"aligned":true,"deviation":""}`;

/**
 * 捕获用户原始意图（在 on_agent_start 时调用）
 */
export function captureBaselineIntent(sessionKey: string, originalInput: string): BaselineIntent {
  return {
    sessionKey,
    originalInput,
    capturedAt: Date.now(),
  };
}

/**
 * 执行意图对齐校验
 * 将 Agent 当前规划与基准意图进行语义比对
 */
export async function checkIntentAlignment(
  gateway: ModelGateway,
  baseline: BaselineIntent,
  currentPlan: string,
): Promise<IntentAlignmentResult> {
  // 如果 Slow Path 不可用，直接 fail-open
  if (!gateway.isEnabled()) {
    return { aligned: true, confidence: 1.0, verdict: "safe" };
  }

  const systemPrompt = loadSystemPrompt();
  const userContent = buildVerificationPayload(baseline.originalInput, currentPlan);

  const result = await gateway.safeVerify(systemPrompt, userContent, 512);

  // 网关不可用时 fail-open
  if (!result) {
    return { aligned: true, confidence: 1.0, verdict: "safe" };
  }

  const parsed = parseAlignmentResult(result.content);

  // 当检测到劫持时，将可疑计划片段附加到 deviation，方便审计溯源
  if (parsed.verdict === "hijacked") {
    const planSnippet = currentPlan.slice(0, 200);
    parsed.deviation = parsed.deviation
      ? `${parsed.deviation} [可疑计划：${planSnippet}]`
      : planSnippet;
  }

  return parsed;
}

function buildVerificationPayload(originalIntent: string, currentPlan: string): string {
  return `## 用户原始意图
${originalIntent}

## Agent 当前计划
${currentPlan}

请判断两者的语义一致性，并输出 JSON 格式的判断结果。`;
}

function parseAlignmentResult(content: string): IntentAlignmentResult {
  try {
    // 提取 JSON（可能包含 markdown 代码块）
    const jsonMatch = content.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error("无法解析响应");

    const parsed = JSON.parse(jsonMatch[0]) as {
      verdict?: string;
      confidence?: number;
      aligned?: boolean;
      deviation?: string;
    };

    const verdict = (["safe", "suspect", "hijacked"] as const).includes(parsed.verdict as never)
      ? (parsed.verdict as IntentAlignmentResult["verdict"])
      : "safe";

    const confidence = typeof parsed.confidence === "number"
      ? Math.max(0, Math.min(1, parsed.confidence))
      : 1.0;

    return {
      aligned: verdict !== "hijacked",
      confidence,
      verdict,
      deviation: parsed.deviation,
    };
  } catch {
    // 解析失败时 fail-open
    return { aligned: true, confidence: 1.0, verdict: "safe" };
  }
}
