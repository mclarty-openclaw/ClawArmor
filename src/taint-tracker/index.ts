// ============================================================
// ClawArmor 污点追踪器
// 职责：标记外部不可信数据，追踪污点传播，阻断低完整性数据驱动高权限调用
// ============================================================

import type { TaintLevel, TaintedValue, TaintRegistry } from "../types/index.js";

// 被认定为"高权限"工具的名称模式（一旦由低完整性数据驱动即触发阻断）
const HIGH_PRIVILEGE_TOOL_PATTERNS = [
  /^exec$/i,
  /^shell$/i,
  /^bash$/i,
  /^run_command$/i,
  /^execute_code$/i,
  /^write_file$/i,
  /^delete_file$/i,
  /^computer$/i,
  /^str_replace_editor$/i,
] as const;

// 被认定为"外部不可信来源"的工具名称模式
const EXTERNAL_SOURCE_TOOL_PATTERNS = [
  /^web_fetch$/i,
  /^web_search$/i,
  /^browser$/i,
  /^firecrawl_/i,
  /^tavily_/i,
  /^api$/i,
  /^http_request$/i,
  /^url_fetch$/i,
] as const;

// 污点级别数值（用于比较严重程度）
const TAINT_LEVEL_SCORE: Record<TaintLevel, number> = {
  clean: 0,
  low: 1,
  medium: 2,
  high: 3,
};

export class TaintTracker {
  private readonly registry: TaintRegistry = new Map();

  /**
   * 判断工具是否属于外部不可信来源
   */
  isExternalSource(toolName: string): boolean {
    return EXTERNAL_SOURCE_TOOL_PATTERNS.some((pattern) => pattern.test(toolName));
  }

  /**
   * 判断工具是否属于高权限工具
   */
  isHighPrivilegeTool(toolName: string): boolean {
    return HIGH_PRIVILEGE_TOOL_PATTERNS.some((pattern) => pattern.test(toolName));
  }

  /**
   * 将字符串值标记为污点
   */
  taint(id: string, value: string, level: TaintLevel, source: string): void {
    const existing = this.registry.get(id);
    // 如果已存在，取更高级别
    if (existing && TAINT_LEVEL_SCORE[existing.level] >= TAINT_LEVEL_SCORE[level]) {
      return;
    }
    this.registry.set(id, {
      value,
      level,
      source,
      timestamp: Date.now(),
    });
  }

  /**
   * 将工具返回内容整体标记为低完整性
   */
  taintToolResult(toolName: string, resultText: string): void {
    const level: TaintLevel = this.isExternalSource(toolName) ? "low" : "clean";
    if (level === "clean") return;
    // 用内容哈希作为 key，存储污点信息
    const id = `tool-result:${toolName}:${Date.now()}`;
    this.taint(id, resultText.slice(0, 256), level, toolName);
  }

  /**
   * 检查工具调用参数中是否包含污点数据
   * 返回匹配到的污点条目
   */
  inspectToolCallArgs(toolName: string, params: Record<string, unknown>): TaintedValue[] {
    const paramsText = JSON.stringify(params);
    const matches: TaintedValue[] = [];
    for (const [, tainted] of this.registry) {
      if (tainted.level === "clean") continue;
      // 检查参数字符串是否包含已知污点值的片段（取前 64 字符作为指纹）
      const fingerprint = tainted.value.slice(0, 64).trim();
      if (fingerprint.length >= 8 && paramsText.includes(fingerprint)) {
        matches.push(tainted);
      }
    }
    return matches;
  }

  /**
   * 核心校验：低完整性数据 -> 高权限工具 = 违规
   */
  checkControlFlowViolation(
    toolName: string,
    params: Record<string, unknown>,
  ): { violated: boolean; reason?: string; taintedArgs: TaintedValue[] } {
    if (!this.isHighPrivilegeTool(toolName)) {
      return { violated: false, taintedArgs: [] };
    }
    const taintedArgs = this.inspectToolCallArgs(toolName, params);
    const hasLowIntegrity = taintedArgs.some(
      (t) => TAINT_LEVEL_SCORE[t.level] >= TAINT_LEVEL_SCORE["low"],
    );
    if (!hasLowIntegrity) {
      return { violated: false, taintedArgs };
    }
    const sources = [...new Set(taintedArgs.map((t) => t.source))].join(", ");
    return {
      violated: true,
      reason: `高权限工具 "${toolName}" 的参数包含来自不可信来源（${sources}）的低完整性数据，已阻断控制流跳转。`,
      taintedArgs,
    };
  }

  /**
   * 清除所有污点记录（用于会话结束时）
   */
  clear(): void {
    this.registry.clear();
  }

  /**
   * 获取当前注册表快照
   */
  snapshot(): TaintedValue[] {
    return [...this.registry.values()];
  }
}
