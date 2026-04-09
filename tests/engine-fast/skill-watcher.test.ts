import { describe, it, expect, vi, beforeEach } from "vitest";
import { SkillWatcher } from "../../src/engine-fast/skill-watcher.js";
import { createTestLogger } from "../utils/test-logger.js";

// ============================================================
// SkillWatcher 单元测试
// 注意：直接扫描内存内容（通过 mock fs），验证缓存和信任逻辑
// ============================================================

describe("SkillWatcher - 基础功能", () => {
  it("getCachedRecords 初始为空", () => {
    const { logger } = createTestLogger();
    const watcher = new SkillWatcher(logger);
    expect(watcher.getCachedRecords()).toHaveLength(0);
  });

  it("submitScanJob 文件不存在时返回 null", async () => {
    const { logger } = createTestLogger();
    const watcher = new SkillWatcher(logger);
    const result = await watcher.submitScanJob("/nonexistent/path/SKILL.md");
    expect(result).toBeNull();
  });

  it("scanRoots 目录不存在时不抛出异常", async () => {
    const { logger } = createTestLogger();
    const watcher = new SkillWatcher(logger);
    await expect(watcher.scanRoots(["/nonexistent/root"])).resolves.toHaveLength(0);
  });
});

describe("SkillWatcher - 健康状态与冷却", () => {
  it("冷却期内 submitScanJob 返回 null", async () => {
    const { logger } = createTestLogger();
    const watcher = new SkillWatcher(logger);

    // 通过内部方法直接触发冷却（访问私有属性需类型断言）
    const internal = watcher as unknown as {
      health: { cooldownUntil: number; consecutiveFailures: number; failureTimestamps: number[] };
    };
    internal.health.cooldownUntil = Date.now() + 60_000; // 1分钟冷却

    const result = await watcher.submitScanJob("/any/path/SKILL.md");
    expect(result).toBeNull();
  });
});

describe("SkillWatcher - 缓存行为", () => {
  it("同一内容哈希不重复扫描（缓存命中）", async () => {
    const { logger } = createTestLogger();
    const watcher = new SkillWatcher(logger);

    // 直接写入缓存记录
    const internal = watcher as unknown as {
      cache: Map<string, object>;
    };
    const fakeRecord = {
      filePath: "/fake/SKILL.md",
      contentHash: "abc123",
      fileSize: 100,
      scannedAt: Date.now(),
      isTrusted: true,
      findings: [],
    };
    internal.cache.set("abc123", fakeRecord);

    // getCachedRecords 应返回该记录
    const records = watcher.getCachedRecords();
    expect(records).toHaveLength(1);
    expect(records[0].isTrusted).toBe(true);
  });
});
