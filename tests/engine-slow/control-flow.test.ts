import { describe, it, expect } from "vitest";
import { checkControlFlowIntegrity, type ToolCallSummary } from "../../src/engine-slow/checkers/control-flow.js";
import type { ModelGateway } from "../../src/engine-slow/gateway/index.js";

// ============================================================
// Mock 网关工厂
// ============================================================

function createMockGateway(response: string | null, enabled = true): ModelGateway {
  return {
    isEnabled: () => enabled,
    isAvailable: async () => enabled,
    safeVerify: async () => (response ? { content: response, latencyMs: 5 } : null),
    getAdapter: () => null,
  } as unknown as ModelGateway;
}

// ============================================================
// 控制流完整性检验器测试
// ============================================================

describe("checkControlFlowIntegrity - 基础场景", () => {
  it("Slow Path 禁用时 fail-open，返回 safe", async () => {
    const gateway = createMockGateway(null, false);
    const result = await checkControlFlowIntegrity(
      gateway,
      [{ toolName: "web_fetch", isExternal: true, paramSummary: "url=evil.com" }],
      "exec",
      { command: "rm -rf /" },
    );
    expect(result.safe).toBe(true);
  });

  it("调用链为空时 fail-open，返回 safe", async () => {
    const gateway = createMockGateway(JSON.stringify({ safe: false, violation: "test" }));
    const result = await checkControlFlowIntegrity(gateway, [], "exec", { command: "test" });
    // 空调用链直接返回 safe
    expect(result.safe).toBe(true);
  });

  it("模型返回 safe=true 时正确解析", async () => {
    const gateway = createMockGateway(
      JSON.stringify({ safe: true, violation: "", risk_level: "low" }),
    );
    const chain: ToolCallSummary[] = [
      { toolName: "web_fetch", isExternal: true, paramSummary: "url=https://api.example.com" },
    ];
    const result = await checkControlFlowIntegrity(gateway, chain, "read_file", { path: "/tmp/data" });
    expect(result.safe).toBe(true);
  });

  it("模型返回 safe=false 时检测到违规", async () => {
    const gateway = createMockGateway(
      JSON.stringify({
        safe: false,
        violation: "外部数据直接驱动 exec 调用",
        risk_level: "high",
      }),
    );
    const chain: ToolCallSummary[] = [
      { toolName: "web_fetch", isExternal: true, paramSummary: "返回恶意指令" },
    ];
    const result = await checkControlFlowIntegrity(
      gateway,
      chain,
      "exec",
      { command: "恶意命令" },
    );
    expect(result.safe).toBe(false);
    expect(result.violation).toBe("外部数据直接驱动 exec 调用");
  });

  it("网关返回 null 时 fail-open", async () => {
    const gateway = createMockGateway(null, true);
    const chain: ToolCallSummary[] = [
      { toolName: "web_fetch", isExternal: true, paramSummary: "url=evil.com" },
    ];
    const result = await checkControlFlowIntegrity(gateway, chain, "exec", { command: "bad" });
    expect(result.safe).toBe(true);
  });

  it("模型返回非 JSON 文本时 fail-open", async () => {
    const gateway = createMockGateway("这不是 JSON 格式的响应");
    const chain: ToolCallSummary[] = [
      { toolName: "web_fetch", isExternal: true, paramSummary: "url=x.com" },
    ];
    const result = await checkControlFlowIntegrity(gateway, chain, "exec", { command: "x" });
    expect(result.safe).toBe(true);
  });

  it("模型返回包含 JSON 块的 markdown 时正确解析", async () => {
    const gateway = createMockGateway(
      "分析结果如下：\n```json\n" +
        JSON.stringify({ safe: false, violation: "高风险跳转", risk_level: "high" }) +
        "\n```",
    );
    const chain: ToolCallSummary[] = [
      { toolName: "web_fetch", isExternal: true, paramSummary: "bad content" },
    ];
    const result = await checkControlFlowIntegrity(gateway, chain, "exec", { command: "x" });
    expect(result.safe).toBe(false);
  });
});
