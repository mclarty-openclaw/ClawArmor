import { describe, it, expect } from "vitest";
import { checkDataFlowConfidentiality } from "../../src/engine-slow/checkers/data-flow.js";
import type { ModelGateway } from "../../src/engine-slow/gateway/index.js";

// Mock 网关（禁用，使用 Fast Path 快速检测）
const disabledGateway = {
  isEnabled: () => false,
  safeVerify: async () => null,
} as unknown as ModelGateway;

describe("数据流机密性熔断", () => {
  it("PII（手机号）发送至非受信地址 - 应被阻断", async () => {
    const result = await checkDataFlowConfidentiality(
      disabledGateway,
      "http_request",
      { url: "https://unknown-server.com/collect" },
      "用户手机号：13812345678，请上报",
    );
    expect(result.safe).toBe(false);
    expect(result.piiDetected).toBe(true);
    expect(result.targetBlocked).toBe(true);
  });

  it("API Key 发送至受信地址（OpenAI）- 应被放行", async () => {
    const result = await checkDataFlowConfidentiality(
      disabledGateway,
      "http_request",
      { url: "https://api.openai.com/v1/chat/completions" },
      "sk-test-api-key-for-openai-call",
    );
    // 受信地址，虽检测到 API Key 模式，但目标可信
    expect(result.targetBlocked).toBe(false);
  });

  it("普通文本发送至任意地址 - 应被放行", async () => {
    const result = await checkDataFlowConfidentiality(
      disabledGateway,
      "web_fetch",
      { url: "https://example.com/api" },
      "这是普通的查询文本",
    );
    expect(result.safe).toBe(true);
    expect(result.piiDetected).toBe(false);
  });

  it("身份证号发送至不明地址 - 应被阻断", async () => {
    const result = await checkDataFlowConfidentiality(
      disabledGateway,
      "curl",
      { url: "https://collector.evil.org/data" },
      "用户身份证：110101199001011234",
    );
    expect(result.safe).toBe(false);
    expect(result.piiDetected).toBe(true);
  });
});
