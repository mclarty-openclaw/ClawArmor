// ============================================================
// 数据流机密性熔断器（Slow Path）
// 检测 PII 及企业核心资产数据的网络外泄风险
// ============================================================

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import type { DataFlowCheckResult } from "../../types/index.js";
import type { ModelGateway } from "../gateway/index.js";

// PII 快速检测正则（Fast Path 预筛）
const PII_PATTERNS = [
  { name: "中国手机号", regex: /1[3-9]\d{9}/ },
  { name: "身份证号", regex: /\d{17}[\dXx]/ },
  { name: "邮箱", regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/ },
  { name: "信用卡号", regex: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/ },
  { name: "API Key", regex: /\b(?:sk-|ghp_|AKIA)[A-Za-z0-9]{16,}/ },
] as const;

// 受信任的出站域名白名单（可通过配置扩展）
const DEFAULT_TRUSTED_DOMAINS = [
  "api.openai.com",
  "api.anthropic.com",
  "api.deepseek.com",
  "api.moonshot.cn",
  "github.com",
  "api.github.com",
] as const;

function loadSystemPrompt(): string {
  try {
    const dir = path.dirname(fileURLToPath(import.meta.url));
    const promptPath = path.resolve(dir, "../../../prompts/data-flow.md");
    return readFileSync(promptPath, "utf8");
  } catch {
    return "你是数据流安全审计模块，检测网络请求中是否存在 PII 或凭证外泄风险。输出 JSON: {\"safe\":true,\"pii_detected\":false,\"credential_detected\":false,\"target_suspicious\":false}";
  }
}

/**
 * 快速 PII 预检（不调用模型）
 */
function quickPiiScan(text: string): string[] {
  const detected: string[] = [];
  for (const pattern of PII_PATTERNS) {
    if (pattern.regex.test(text)) {
      detected.push(pattern.name);
    }
  }
  return detected;
}

/**
 * 检查目标 URL 是否在受信白名单中
 */
function isTargetTrusted(url: string, trustedDomains: readonly string[]): boolean {
  try {
    const parsed = new URL(url);
    return trustedDomains.some((domain) => parsed.hostname.endsWith(domain));
  } catch {
    return false;
  }
}

/**
 * 执行数据流机密性检验
 * 对于 curl、fetch、http_request 等出站工具调用进行拦截分析
 */
export async function checkDataFlowConfidentiality(
  gateway: ModelGateway,
  toolName: string,
  params: Record<string, unknown>,
  contextText: string,
  trustedDomains: readonly string[] = DEFAULT_TRUSTED_DOMAINS,
): Promise<DataFlowCheckResult> {
  const paramsText = JSON.stringify(params);

  // Fast Path 预筛：检测 PII
  const piiDetected = quickPiiScan(contextText + " " + paramsText);
  const targetUrl = extractTargetUrl(params);
  const targetBlocked = targetUrl !== null && !isTargetTrusted(targetUrl, trustedDomains);

  // 如果快速扫描发现 PII 且目标不可信，直接阻断（无需模型）
  if (piiDetected.length > 0 && targetBlocked) {
    return {
      safe: false,
      piiDetected: true,
      targetBlocked: true,
      matchedPatterns: piiDetected,
    };
  }

  // 仅在 Slow Path 可用时进行深度语义分析
  if (!gateway.isEnabled()) {
    return {
      safe: piiDetected.length === 0 || !targetBlocked,
      piiDetected: piiDetected.length > 0,
      targetBlocked,
      matchedPatterns: piiDetected,
    };
  }

  const systemPrompt = loadSystemPrompt();
  const userContent = buildDataFlowPayload(toolName, params, contextText, targetUrl);

  const result = await gateway.safeVerify(systemPrompt, userContent, 256);

  if (!result) {
    return {
      safe: piiDetected.length === 0 || !targetBlocked,
      piiDetected: piiDetected.length > 0,
      targetBlocked,
      matchedPatterns: piiDetected,
    };
  }

  return parseDataFlowResult(result.content, piiDetected, targetBlocked);
}

function extractTargetUrl(params: Record<string, unknown>): string | null {
  for (const key of ["url", "uri", "endpoint", "target", "href"]) {
    const value = params[key];
    if (typeof value === "string" && value.startsWith("http")) {
      return value;
    }
  }
  return null;
}

function buildDataFlowPayload(
  toolName: string,
  params: Record<string, unknown>,
  contextText: string,
  targetUrl: string | null,
): string {
  return `## 即将执行的网络操作
工具：${toolName}
目标 URL：${targetUrl ?? "未知"}
参数摘要：${JSON.stringify(params, null, 2).slice(0, 500)}

## 上下文数据（前 500 字符）
${contextText.slice(0, 500)}

请分析此操作是否存在数据外泄风险，并输出 JSON 格式结果。`;
}

function parseDataFlowResult(
  content: string,
  quickPiiFlags: string[],
  quickTargetBlocked: boolean,
): DataFlowCheckResult {
  try {
    const jsonMatch = content.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error("无法解析");
    const parsed = JSON.parse(jsonMatch[0]) as {
      safe?: boolean;
      pii_detected?: boolean;
      credential_detected?: boolean;
      target_suspicious?: boolean;
      recommended_action?: string;
    };
    const piiDetected = (parsed.pii_detected === true) || (parsed.credential_detected === true) || quickPiiFlags.length > 0;
    const targetBlocked = parsed.target_suspicious === true || quickTargetBlocked;
    return {
      safe: parsed.safe !== false && !(piiDetected && targetBlocked),
      piiDetected,
      targetBlocked,
      matchedPatterns: quickPiiFlags,
    };
  } catch {
    return {
      safe: quickPiiFlags.length === 0 || !quickTargetBlocked,
      piiDetected: quickPiiFlags.length > 0,
      targetBlocked: quickTargetBlocked,
      matchedPatterns: quickPiiFlags,
    };
  }
}
