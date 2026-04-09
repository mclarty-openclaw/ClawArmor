// ============================================================
// 控制流完整性检验器（Slow Path）
// 解析工具调用链，识别低信任 → 高权限的非法跳转路径
// ============================================================

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import type { ControlFlowCheckResult } from "../../types/index.js";
import type { ModelGateway } from "../gateway/index.js";

function loadSystemPrompt(): string {
  try {
    const dir = path.dirname(fileURLToPath(import.meta.url));
    const promptPath = path.resolve(dir, "../../../prompts/control-flow.md");
    return readFileSync(promptPath, "utf8");
  } catch {
    return "你是控制流安全审计模块，分析工具调用链是否存在低信任数据驱动高权限操作的风险。输出 JSON: {\"safe\":true,\"violation\":\"\",\"risk_level\":\"low\"}";
  }
}

export type ToolCallSummary = {
  toolName: string;
  isExternal: boolean;
  paramSummary: string;
};

/**
 * 通过旁路模型检验工具调用链的控制流完整性
 */
export async function checkControlFlowIntegrity(
  gateway: ModelGateway,
  callChain: ToolCallSummary[],
  currentTool: string,
  currentParams: Record<string, unknown>,
): Promise<ControlFlowCheckResult> {
  if (!gateway.isEnabled() || callChain.length === 0) {
    return { safe: true, taintedArgs: [] };
  }

  const systemPrompt = loadSystemPrompt();
  const userContent = buildControlFlowPayload(callChain, currentTool, currentParams);

  const result = await gateway.safeVerify(systemPrompt, userContent, 256);

  if (!result) {
    return { safe: true, taintedArgs: [] };
  }

  return parseControlFlowResult(result.content);
}

function buildControlFlowPayload(
  callChain: ToolCallSummary[],
  currentTool: string,
  currentParams: Record<string, unknown>,
): string {
  const chainDesc = callChain
    .map((c, i) => `${i + 1}. [${c.isExternal ? "外部" : "内部"}] ${c.toolName}: ${c.paramSummary}`)
    .join("\n");

  return `## 历史工具调用链
${chainDesc}

## 当前即将调用的工具
工具名：${currentTool}
参数：${JSON.stringify(currentParams, null, 2).slice(0, 1000)}

请分析此调用链是否存在控制流完整性违规，并输出 JSON 格式结果。`;
}

function parseControlFlowResult(content: string): ControlFlowCheckResult {
  try {
    const jsonMatch = content.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error("无法解析");
    const parsed = JSON.parse(jsonMatch[0]) as {
      safe?: boolean;
      violation?: string;
      risk_level?: string;
    };
    return {
      safe: parsed.safe !== false,
      violation: parsed.violation,
      taintedArgs: [],
    };
  } catch {
    return { safe: true, taintedArgs: [] };
  }
}
