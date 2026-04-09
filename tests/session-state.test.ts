import { describe, it, expect, vi } from "vitest";
import { SessionStateManager } from "../src/session-state.js";
import { createTestLogger } from "./utils/test-logger.js";

// ============================================================
// SessionStateManager 单元测试
// ============================================================

function makeManager(clockFn?: () => number) {
  const { logger } = createTestLogger();
  return new SessionStateManager("/tmp/test-state", logger, clockFn);
}

describe("SessionStateManager - 回合信号", () => {
  it("首次 appendTurnFlags 创建新记录", () => {
    const mgr = makeManager();
    const signals = mgr.appendTurnFlags("sess-1", {
      injectionFlags: ["ignore-prev-en"],
    });
    expect(signals.injectionFlags).toContain("ignore-prev-en");
    expect(signals.needsPromptPrepend).toBe(true);
  });

  it("多次 appendTurnFlags 合并去重", () => {
    const mgr = makeManager();
    mgr.appendTurnFlags("sess-1", { injectionFlags: ["flag-a"] });
    mgr.appendTurnFlags("sess-1", { injectionFlags: ["flag-a", "flag-b"] });
    const signals = mgr.peekTurnSignals("sess-1");
    expect(signals!.injectionFlags).toHaveLength(2);
    expect(signals!.injectionFlags).toContain("flag-a");
    expect(signals!.injectionFlags).toContain("flag-b");
  });

  it("peekTurnSignals 不消耗记录", () => {
    const mgr = makeManager();
    mgr.appendTurnFlags("sess-1", { injectionFlags: ["x"] });
    mgr.peekTurnSignals("sess-1");
    // 再次 peek 仍存在
    expect(mgr.peekTurnSignals("sess-1")).not.toBeUndefined();
  });

  it("consumeTurnSignals 消耗后返回 undefined", () => {
    const mgr = makeManager();
    mgr.appendTurnFlags("sess-1", { injectionFlags: ["x"] });
    const consumed = mgr.consumeTurnSignals("sess-1");
    expect(consumed!.injectionFlags).toContain("x");
    expect(mgr.peekTurnSignals("sess-1")).toBeUndefined();
  });

  it("hasExternalToolResult 为 true 时 needsPromptPrepend 为 true", () => {
    const mgr = makeManager();
    const signals = mgr.appendTurnFlags("sess-1", { hasExternalToolResult: true });
    expect(signals.needsPromptPrepend).toBe(true);
  });

  it("TTL 到期后自动淘汰", () => {
    let now = Date.now();
    const clock = () => now;
    const mgr = makeManager(clock);

    mgr.appendTurnFlags("sess-ttl", { injectionFlags: ["x"] });
    // 推进 6 分钟（超过 5 分钟 TTL）
    now += 6 * 60_000;

    // 触发淘汰（appendTurnFlags 会调用 evict）
    mgr.appendTurnFlags("sess-other", { injectionFlags: ["y"] });
    expect(mgr.peekTurnSignals("sess-ttl")).toBeUndefined();
  });
});

describe("SessionStateManager - Run 信号", () => {
  it("appendRunSignals 追加多次后合并去重", () => {
    const mgr = makeManager();
    mgr.appendRunSignals("run-1", { sourceSignals: ["sig-a"], sessionKey: "sess-1" });
    mgr.appendRunSignals("run-1", { sourceSignals: ["sig-a", "sig-b"], sinkSignals: ["sink-x"] });
    const signals = mgr.peekRunSignals("run-1");
    expect(signals!.sourceSignals).toHaveLength(2);
    expect(signals!.sinkSignals).toContain("sink-x");
    expect(signals!.sessionKey).toBe("sess-1");
  });

  it("不同 runId 的信号互相隔离", () => {
    const mgr = makeManager();
    mgr.appendRunSignals("run-A", { sourceSignals: ["a"] });
    mgr.appendRunSignals("run-B", { sinkSignals: ["b"] });
    expect(mgr.peekRunSignals("run-A")!.sinkSignals).toHaveLength(0);
    expect(mgr.peekRunSignals("run-B")!.sourceSignals).toHaveLength(0);
  });
});

describe("SessionStateManager - 密钥观测", () => {
  it("recordObservedSecrets 记录并返回长度≥8 的密钥", () => {
    const mgr = makeManager();
    const secrets = mgr.recordObservedSecrets("sess-1", ["short", "sk-abcdefghijk", "another-long-secret"]);
    expect(secrets).toContain("sk-abcdefghijk");
    expect(secrets).toContain("another-long-secret");
    expect(secrets).not.toContain("short");
  });

  it("多次记录合并去重，按长度降序排列", () => {
    const mgr = makeManager();
    mgr.recordObservedSecrets("sess-1", ["short-secret12"]);
    mgr.recordObservedSecrets("sess-1", ["longer-secret-value-123"]);
    const secrets = mgr.getObservedSecrets("sess-1");
    expect(secrets[0].length).toBeGreaterThanOrEqual(secrets[secrets.length - 1].length);
  });

  it("getObservedSecrets 不存在时返回空数组", () => {
    const mgr = makeManager();
    expect(mgr.getObservedSecrets("no-such-session")).toHaveLength(0);
  });
});

describe("SessionStateManager - 循环计数器", () => {
  it("incrementLoopCounter 累计计数", () => {
    const mgr = makeManager();
    expect(mgr.incrementLoopCounter("run-1", "exec")).toBe(1);
    expect(mgr.incrementLoopCounter("run-1", "exec")).toBe(2);
    expect(mgr.incrementLoopCounter("run-1", "exec")).toBe(3);
  });

  it("不同工具的计数相互独立", () => {
    const mgr = makeManager();
    mgr.incrementLoopCounter("run-1", "exec");
    mgr.incrementLoopCounter("run-1", "write_file");
    expect(mgr.getLoopCount("run-1", "exec")).toBe(1);
    expect(mgr.getLoopCount("run-1", "write_file")).toBe(1);
  });
});

describe("SessionStateManager - Skill 信任", () => {
  it("recordTrustedSkill + isTrustedSkill 正常工作", () => {
    const mgr = makeManager();
    expect(mgr.isTrustedSkill("hash-abc")).toBe(false);
    mgr.recordTrustedSkill({
      filePath: "/path/to/SKILL.md",
      contentHash: "hash-abc",
      fileSize: 1024,
      scannedAt: Date.now(),
    });
    expect(mgr.isTrustedSkill("hash-abc")).toBe(true);
  });
});

describe("SessionStateManager - 清理", () => {
  it("clearSession 清除该 session 的所有数据", () => {
    const mgr = makeManager();
    mgr.appendTurnFlags("sess-clean", { injectionFlags: ["x"] });
    mgr.recordObservedSecrets("sess-clean", ["secret12345678"]);
    mgr.appendRunSignals("run-clean", { sessionKey: "sess-clean", sourceSignals: ["s"] });

    mgr.clearSession("sess-clean");
    expect(mgr.peekTurnSignals("sess-clean")).toBeUndefined();
    expect(mgr.getObservedSecrets("sess-clean")).toHaveLength(0);
    expect(mgr.peekRunSignals("run-clean")).toBeUndefined();
  });

  it("clearRun 只清除指定 run 数据", () => {
    const mgr = makeManager();
    mgr.appendRunSignals("run-del", { sourceSignals: ["s"] });
    mgr.appendRunSignals("run-keep", { sourceSignals: ["s"] });

    mgr.clearRun("run-del");
    expect(mgr.peekRunSignals("run-del")).toBeUndefined();
    expect(mgr.peekRunSignals("run-keep")).not.toBeUndefined();
  });
});
